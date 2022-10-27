#include "scopeDescriptor.hpp"

#include "opto/locknode.hpp"

#include "llvmCodeGen.hpp"

ScopeDescriptor::ScopeDescriptor(LlvmCodeGen* code_gen) : _cg(code_gen), C(code_gen->C) {}

void ScopeDescriptor::describe_scopes() {
  C->env()->debug_info()->set_oopmaps(C->oop_map_set());
  for (std::unique_ptr<DebugInfo>& debug_info : cg()->debug_info()) {
    SafePointDebugInfo* di = debug_info->asSafePoint();
    if (!di) continue;
    RecordAccessor record = di->record(cg()->sm_parser());
    LocationAccessor deopt_cnt = record.getLocation(DEOPT_CNT_OFFSET);
    uint32_t gc_idx = deopt_cnt.getSmallConstant() + DEOPT_OFFSET;
    int la_idx = describe_scope(di);
    if (!C->has_method()) continue;
    assert(la_idx == gc_idx, "sanity check");
    std::unordered_map<int, bool> oop_map;
    for (uint16_t i = gc_idx; i < record.getNumLocations(); i += 2) {
      int off[2];
      bool skip = false;
      for (size_t j = 0; j < 2; ++j) {
        LocationAccessor la = record.getLocation(i + j);
        if (la.getKind() != LocationKind::Indirect) {
          assert(la.getKind() == LocationKind::Constant && la.getSmallConstant() == 0, "no other choice");
          skip = true;
          break;
        }
        assert(la.getSizeInBytes() == cg()->selector().pointer_size() >> LogBytesPerWord, "only support singular locations");
        off[j] = stack_offset(la);
      }
      if (skip) continue;
      if (off[0] == off[1]) {
        oop_map[off[0]] = true;
      } else if (!oop_map.count(off[0])) {
        oop_map.insert({ off[0], false });
      }
      // set_oop is called if arguments are equal
      di->oopmap->set_derived_oop(VMRegImpl::stack2reg(off[1] / BytesPerInt), VMRegImpl::stack2reg(off[0] / BytesPerInt));
    }
    for (const auto& pair : oop_map) {
      if (!pair.second) {
        VMReg oop_reg = VMRegImpl::stack2reg(pair.first / BytesPerInt);
        di->oopmap->set_derived_oop(oop_reg, oop_reg);
      }
    }
  }
}

int ScopeDescriptor::stack_offset(LocationAccessor la) {
  assert(la.getKind() == LocationKind::Indirect, "these are values located on stack");
  if (la.getDwarfRegNum() == RSP) return la.getOffset();
  if (la.getDwarfRegNum() == RBP) return la.getOffset() + cg()->stack().unext_offset();
  Unimplemented();
}

void ScopeDescriptor::fill_loc_array(GrowableArray<ScopeValue*> *array, const std::vector<std::unique_ptr<NodeInfo>>& src, SafePointDebugInfo* di, int& la_idx) {
  bool skip = false;
  for (const std::unique_ptr<NodeInfo>& ni : src) {
    if (skip) {
      assert(ni->node == C->top(), "LocArray collision");
      skip = false;
    } else {
      skip = fill_loc_array_helper(array, ni.get(), di, la_idx);
    }
  }
}

bool ScopeDescriptor::fill_loc_array_helper(GrowableArray<ScopeValue*> *array, NodeInfo* ni, SafePointDebugInfo* di, int& la_idx) {
  ScalarObjectInfo* sc_obj = ni->asScalarObjectInfo();
  if (sc_obj) {
    array->append(sc_obj->sc_val);
    fill_loc_array(sc_obj->dest, sc_obj->field_values, di, la_idx);
    return false;
  }
  Node* n = ni->node;
  if (empty_loc(n)) {
    array->append(new LocationValue(Location()));
    return false;
  }
  const Type *t = n->bottom_type();
  ScopeValue* lv;
  bool largeType = false;
  if (con_loc(n)) {
    lv = con_value(t, largeType);
  } else {
    RecordAccessor record = di->record(cg()->sm_parser());
    LocationAccessor la = record.getLocation(la_idx++);
    Selector& sel = cg()->selector();
    lv = [&] {
      LocationKind lk = la.getKind();
      if (lk == LocationKind::Indirect) {
        llvm::Value* v = sel.select_node(n);
        Location::Type type = [&] {
          switch (t->base()) {
            case Type::DoubleBot:
            case Type::DoubleCon:
              largeType = true;
              return Location::dbl;
            case Type::Long:
              largeType = true;
              return Location::lng;
            case Type::RawPtr:
              return Location::lng;
            case Type::FloatBot:
            case Type::FloatCon:
            case Type::Int:
              return Location::normal;
            case Type::NarrowOop:
              return Location::narrowoop;
            default:
              std::vector<Node*>& oops = cg()->selector().oops();
              auto it = std::find(oops.begin(), oops.end(), n);
              return it != oops.end() ? Location::oop : Location::normal;
          }
        } ();
        int offset = stack_offset(la);
        // std::vector<Node*>& narrow_oops = cg()->selector().narrow_oops();
        // if (std::find(narrow_oops.begin(), narrow_oops.end(), n) != narrow_oops.end()) {
        //   assert(type == Location::narrowoop, "sanity check");
        //   di->oopmap->set_narrowoop(VMRegImpl::stack2reg(offset / BytesPerInt));
        // }
        Location loc = Location::new_stk_loc(type, offset);
        return (ScopeValue*)new LocationValue(loc); 
      } else if (lk == LocationKind::Constant || lk == LocationKind::ConstantIndex) {
        return con_value(t, largeType);
      }
      Unimplemented();
    } ();
  }
  if (largeType) { array->append(new ConstantIntValue(0)); }
  array->append(lv);
  return largeType;
}

ScopeValue* ScopeDescriptor::con_value(const Type *t, bool& largeType) {
  // No register.  It must be constant data.
  switch (t->base()) {
    case Type::Half:              // Second half of a double
      ShouldNotReachHere();       // Caller should skip 2nd halves
    case Type::AnyPtr:
      return new ConstantOopWriteValue(NULL);
    case Type::AryPtr:
    case Type::InstPtr:          // fall through
      return new ConstantOopWriteValue(t->isa_oopptr()->const_oop()->constant_encoding());
    case Type::NarrowOop:
      if (t == TypeNarrowOop::NULL_PTR) {
        return new ConstantOopWriteValue(NULL);
      } 
      return new ConstantOopWriteValue(t->make_ptr()->isa_oopptr()->const_oop()->constant_encoding());
    case Type::Int:
      return new ConstantIntValue(t->is_int()->get_con());
    case Type::RawPtr:
      // A return address (T_ADDRESS).
      assert((intptr_t)t->is_ptr()->get_con() < (intptr_t)0x10000, "must be a valid BCI");
#ifdef _LP64
      // Must be restored to the full-width 64-bit stack slot.
      return new ConstantLongValue(t->is_ptr()->get_con());
#else
      return new ConstantIntValue(t->is_ptr()->get_con());
#endif
    case Type::FloatCon:
      return new ConstantIntValue(jint_cast(t->is_float_constant()->getf()));
    case Type::DoubleCon:
      largeType = true;
      return new ConstantDoubleValue(t->is_double_constant()->getd());
    case Type::Long:
      largeType = true;
      return new ConstantLongValue(t->is_long()->get_con());
    case Type::Top:               // Add an illegal value here
      return new LocationValue(Location());
    default:
      ShouldNotReachHere();
  }
}

int ScopeDescriptor::describe_scope(SafePointDebugInfo* di) {
  LlvmStack& stack = cg()->stack();
  MachSafePointNode* sfn = di->scope_info->sfn;

  C->debug_info()->add_safepoint(di->pc_offset, di->oopmap);

  bool is_method_handle_invoke = false;
  bool return_oop = false;

  // Add the safepoint in the DebugInfoRecorder
  if (sfn->is_MachCall()) {
    MachCallNode* mcall_n = di->scope_info->cn;

    // Is the call a MethodHandle call?
    if (mcall_n->is_MachCallJava()) {
      if (mcall_n->as_MachCallJava()->_method_handle_invoke) {
        assert(C->has_method_handle_invokes(), "must have been set during call generation");
        is_method_handle_invoke = true;
      }
    }

    // Check if a call returns an object.
    // TODO: fix this shit. In the right case we have to precompile c2 runtime to Java-like wrappers
    bool is_runtime_call = mcall_n->ideal_Opcode() == Op_CallStaticJava && mcall_n->as_MachCallJava()->_method == NULL;
    return_oop = mcall_n->returns_pointer() && !is_runtime_call;
  }
  // Loop over the JVMState list to add scope information
  // Do not skip safepoints with a NULL method, they need monitor info
  GrowableArray<ScopeValue*> *objs = di->scope_info->objs;

  int la_idx = DEOPT_OFFSET;
  JVMState* youngest_jvms = sfn->jvms();
  int depth = 0, max_depth = youngest_jvms->depth();
  for (ScopeValueInfo& si : di->scope_info->sv_info) {
    depth++;
    JVMState* jvms = youngest_jvms->of_depth(depth);
    ciMethod* method = jvms->has_method() ? jvms->method() : NULL;
    int num_mon = jvms->nof_monitors();

    GrowableArray<ScopeValue*> *locarray = new GrowableArray<ScopeValue*>(si.locs.size());
    fill_loc_array(locarray, si.locs, di, la_idx);

    GrowableArray<ScopeValue*> *exparray = new GrowableArray<ScopeValue*>(si.exps.size());
    fill_loc_array(exparray, si.exps, di, la_idx);

    GrowableArray<MonitorValue*> *monarray = new GrowableArray<MonitorValue*>(num_mon);
    for(int idx = 0; idx < num_mon; idx++) {
      // Grab the node that defines this monitor
      Node* box_node = sfn->monitor_box(jvms, idx);
      Node* obj_node = sfn->monitor_obj(jvms, idx);
      bool eliminated = (box_node->is_BoxLock() && box_node->as_BoxLock()->is_eliminated());
      int mon_idx = box_node->as_BoxLock()->stack_slot() / 2;

      int mon_object_offset = stack.unextended_mon_obj_offset(mon_idx);

      // Create ScopeValue for object
      ScopeValue *scval = NULL;
      if( obj_node->is_SafePointScalarObject() ) {
        std::unique_ptr<NodeInfo>& mi = si.mons[idx];
        ScalarObjectInfo* sc_obj = mi->asScalarObjectInfo();
        scval = sc_obj->sc_val;
        fill_loc_array(sc_obj->dest, sc_obj->field_values, di, la_idx);
      } else if( !obj_node->is_Con() ) {
        Location::Type oop_type = obj_node->bottom_type()->base() == Type::NarrowOop ? Location::narrowoop : Location::oop;
        scval = new LocationValue(Location::new_stk_loc(oop_type, mon_object_offset));
      } else {
        const TypePtr *tp = obj_node->bottom_type()->make_ptr();
        scval = new ConstantOopWriteValue(tp->is_oopptr()->const_oop()->constant_encoding());
      }

      Location basic_lock = Location::new_stk_loc(Location::normal, stack.unextended_mon_offset(mon_idx));
      monarray->append(new MonitorValue(scval, basic_lock, eliminated));
      if (!obj_node->is_SafePointScalarObject() && !(eliminated && obj_node->is_Con())) {
        di->oopmap->set_oop(VMRegImpl::stack2reg(mon_object_offset / BytesPerInt));
      }
    }

    C->debug_info()->dump_object_pool(objs);

    // Build first class objects to pass to scope
    DebugToken *locvals = C->debug_info()->create_scope_values(locarray);
    DebugToken *expvals = C->debug_info()->create_scope_values(exparray);
    DebugToken *monvals = C->debug_info()->create_monitor_values(monarray);

    // Make method available for all Safepoints
    ciMethod* scope_method = method ? method : C->method();
    // Describe the scope here
    assert(jvms->bci() >= InvocationEntryBci && jvms->bci() <= 0x10000, "must be a valid or entry BCI");
    assert(!jvms->should_reexecute() || depth == max_depth, "reexecute allowed only for the youngest");
    // Now we can describe the scope.
    C->debug_info()->describe_scope(di->pc_offset, scope_method, jvms->bci(), jvms->should_reexecute(), is_method_handle_invoke, return_oop, locvals, expvals, monvals);
  }

  C->debug_info()->end_safepoint(di->pc_offset);
  return la_idx;
}

ScopeInfo* ScopeDescriptor::register_scope(MachSafePointNode* sfn, bool throws_exc) {
  if (throws_exc) {
    std::unique_ptr<ThrowScopeInfo> bsi_uptr = std::make_unique<ThrowScopeInfo>();
    bsi_uptr->bb = cg()->selector().basic_block();
    scope_info().push_back(std::move(bsi_uptr));
  } else {
    std::unique_ptr<ScopeInfo> si_uptr = std::make_unique<ScopeInfo>();
    scope_info().push_back(std::move(si_uptr));
  }
  ScopeInfo* si = scope_info().back().get();
  si->sfn = sfn;
  DebugInfo::Type ty = [&] {
    if (sfn->is_MachCallStaticJava()) return DebugInfo::StaticCall;
    if (sfn->is_MachCallDynamicJava()) return DebugInfo::DynamicCall;
    if (sfn->is_MachCallRuntime()) return DebugInfo::Call;
    return DebugInfo::SafePoint;
  }();
  uint64_t idx = scope_info().size() - 1;
  si->stackmap_id = DebugInfo::id(ty, idx);

  JVMState* youngest_jvms = sfn->jvms();
  si->objs = new GrowableArray<ScopeValue*>();
  int max_depth = youngest_jvms->depth();
  for (int depth = 1; depth <= max_depth; depth++) {
    si->sv_info.emplace_back();
    ScopeValueInfo& svi = si->sv_info.back();
    JVMState* jvms = youngest_jvms->of_depth(depth);
    ciMethod* method = jvms->has_method() ? jvms->method() : NULL;
    // Safepoints that do not have method() set only provide oop-map and monitor info
    // to support GC; these do not support deoptimization.
    int num_locs = (method == NULL) ? 0 : jvms->loc_size();
    int num_exps = (method == NULL) ? 0 : jvms->stk_size();
    assert(method == NULL || jvms->bci() < 0 || num_locs == method->max_locals(),
           "JVMS local count must match that of the method");
    // Add Local and Expression Stack Information

    // Insert locals into the locarray
    svi.locs.reserve(num_locs);
    svi.exps.reserve(num_exps);
    for (int idx = 0; idx < num_locs; ++idx) {
      Node* n = si->sfn->local(jvms, idx);
      svi.locs.push_back(init_node_info(si, n));
    }
    for (int idx = 0; idx < num_exps; ++idx) {
      Node* n = si->sfn->stack(jvms, idx);
      svi.exps.push_back(init_node_info(si, n));
    }
    int num_mon = jvms->nof_monitors();
    svi.mons.reserve(num_mon);
    assert( !method ||
              !method->is_synchronized() ||
              method->is_native() ||
              num_mon > 0 ||
              !GenerateSynchronizationCode,
              "monitors must always exist for synchronized methods");
    for(int idx = 0; idx < num_mon; idx++) {
      Node* obj_node = si->sfn->monitor_obj(jvms, idx); 
      if (obj_node->is_SafePointScalarObject()) {
        svi.mons.push_back(init_node_info(si, obj_node));
      }
    }
  }
  return si;
}

std::unique_ptr<NodeInfo> ScopeDescriptor::init_node_info(ScopeInfo* si, Node* n) {
  if( !n->is_SafePointScalarObject() ) {
    return std::make_unique<NodeInfo>(n);
  }
  std::unique_ptr<ScalarObjectInfo> sc_obj = std::make_unique<ScalarObjectInfo>(n);
  SafePointScalarObjectNode* spobj = n->as_SafePointScalarObject();
  ScopeValue* scval = Compile::sv_for_node_id(si->objs, spobj->_idx);
  if (scval == NULL) {
    const Type *t = n->bottom_type();
    ciKlass* cik = t->is_oopptr()->klass();
    assert(cik->is_instance_klass() ||
            cik->is_array_klass(), "Not supported allocation.");
    ObjectValue* sv = new ObjectValue(spobj->_idx,
      new ConstantOopWriteValue(cik->java_mirror()->constant_encoding()));
    Compile::set_sv_for_object_node(si->objs, sv);

    JVMState* youngest_jvms = si->sfn->jvms();
    uint first_ind = spobj->first_index(youngest_jvms);
    sc_obj->field_values.reserve(spobj->n_fields());
    sc_obj->dest = sv->field_values();
    for (uint i = 0; i < spobj->n_fields(); i++) {
      Node* fn = si->sfn->in(first_ind+i);
      sc_obj->field_values.push_back(init_node_info(si, fn));
    }
    scval = sv;
  }
  sc_obj->sc_val = scval;
  return sc_obj;
}

void ScopeDescriptor::add_statepoint_arg(std::vector<llvm::Value*>& args, NodeInfo* ni) {
  ScalarObjectInfo* sc_obj = ni->asScalarObjectInfo();
  if (sc_obj) {
    for (std::unique_ptr<NodeInfo>& info : sc_obj->field_values) {
      add_statepoint_arg(args, info.get());
    }
  } else if (!empty_loc(ni->node) && !con_loc(ni->node)) {
    llvm::Value* arg = cg()->selector().select_node(ni->node);
    args.push_back(arg);
  }
}

std::vector<llvm::Value*> ScopeDescriptor::stackmap_scope(const ScopeInfo* si) {
  std::vector<llvm::Value*> args;
  for (const ScopeValueInfo& svi : si->sv_info) {
    for (const std::unique_ptr<NodeInfo>& info : svi.locs) {
      add_statepoint_arg(args, info.get());
    }
    for (const std::unique_ptr<NodeInfo>& info : svi.exps) {
      add_statepoint_arg(args, info.get());
    }
    for (const std::unique_ptr<NodeInfo>& info : svi.mons) {
      add_statepoint_arg(args, info.get());
    }
  }
  return args;
}

bool ScopeDescriptor::empty_loc(Node* n) const {
  return n->is_top() || LlvmCodeGen::cmp_ideal_Opcode(n, Op_CreateEx);
}

bool ScopeDescriptor::con_loc(Node* n) const {
  return n->is_Con() && n->is_Type();
}