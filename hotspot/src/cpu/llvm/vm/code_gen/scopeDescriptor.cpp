#include "scopeDescriptor.hpp"

#include "opto/locknode.hpp"

#include "selector_llvm.hpp"

ScopeDescriptor::ScopeDescriptor( Selector* Sel) : sel(Sel), C(sel->C) {}

void ScopeDescriptor::describe_scopes() {
  C->env()->debug_info()->set_oopmaps(C->oop_map_set());
  std::map<uint32_t, RecordAccessor> scopes;
  for (RecordAccessor& record : sel->sm_parser()->records()) {
    scopes.insert(std::pair<uint32_t, RecordAccessor>(record.getInstructionOffset(), record));
  }
  for (auto& rme : scopes) {
    oopmap = new OopMap(sel->frame_size() / wordSize, C->method()->arg_size());
    record = &rme.second;
    sfn = sel->sfns(record->getID());
    pc_offset = rme.first;
    describe_scope();
  }
}

void ScopeDescriptor::fill_loc_array(GrowableArray<ScopeValue*> *array, Node* n) {
  if (n->is_SafePointScalarObject()) {
    for (std::unique_ptr<NodeInfo>& ni : sc_obj->field_values) {
      ScalarObjectInfo* sc_obj_tmp = sc_obj;
      if (ni->is_sc_obj()) {
        sc_obj = ni->as_sc_obj();
        array->append(sc_obj->sc_val);
      }
      fill_loc_array(sc_obj->dest, ni->node);
      sc_obj = sc_obj_tmp;
    }
    return;
  }
  LocationAccessor la  =record->getLocation(la_idx++);
  bool largeType = false;
  llvm::Value* v = sel->select_node_or_const(n);
  llvm::LLVMContext& ctx = sel->ctx();
  Location::Type type = [&] {
    llvm::Type* ty = v->getType();
    if (ty == sel->type(T_DOUBLE)) {
      largeType = true; 
      return Location::Type::dbl;
    }
    if (ty == sel->type(T_LONG)) {
      largeType = true;
      return Location::Type::lng;
    }
    if (ty == sel->type(T_INT)) {
      return Location::Type::normal;
    }
    if (ty == sel->type(T_FLOAT)) {
      return Location::Type::normal;
    }
    if (ty == sel->type(T_OBJECT)) {
      return Location::Type::oop;
    }
    ShouldNotReachHere();
  } ();
  ScopeValue* lv = [&] {
    LocationKind lk = la.getKind();
    if (lk == LocationKind::Indirect) {
      const uint16_t rsp = 7, rbp = 6;
      if (la.getDwarfRegNum() == rsp) {
        max_spill += wordSize; 
        Location loc = Location::new_stk_loc(type, la.getOffset());
        return (ScopeValue*)new LocationValue(loc);
      }
      if (la.getDwarfRegNum() == rbp) {
        max_spill += wordSize; 
        Location loc = Location::new_stk_loc(type, la.getOffset() + sel->frame_size());
        return (ScopeValue*)new LocationValue(loc);
      }
      ShouldNotReachHere();     
    } else if (lk == LocationKind::Constant) {
      if (v == sel->null()) {
        return (ScopeValue*)new LocationValue(Location());
      }
      if (type == Location::oop) { 
        return (ScopeValue*)new ConstantIntValue(la.getSmallConstant()); 
      }
      ShouldNotReachHere();
    } else if (lk == LocationKind::ConstantIndex) {
      uint32_t idx = la.getConstantIndex();
      if (type == Location::oop) {
        jobject const_oop = (jobject)sel->sm_parser()->getConstant(idx).getValue();
        return (ScopeValue*)new ConstantOopWriteValue(const_oop);
      }
      ShouldNotReachHere();
    }
    ShouldNotReachHere();
  } ();
  if (largeType) { array->append(new ConstantIntValue(0)); }
  array->append(lv);
}

void ScopeDescriptor::describe_scope() {
  if (pc_offset < 0) return;  // dead block
  // report extra params

  if (!sel->C->is_osr_compilation()) {
    ciSignature* signature = C->method()->signature();
    int first_mem_param = C->method()->is_static() ? 8 : 7;
    int local_num = 8;
    for (int i = first_mem_param; i < signature->count(); ++i, ++local_num) {
      BasicType bt = signature->type_at(i)->basic_type();
      if (bt == T_OBJECT || bt == T_ARRAY) {
        int offset = local_num * wordSize + sel->frame_size();
        oopmap->set_oop(VMRegImpl::stack2reg(offset / wordSize));
      }
      assert(bt != T_VOID, "check signature");
    }
  }

  C->debug_info()->add_safepoint(pc_offset, oopmap);

  bool is_method_handle_invoke = false;
  bool return_oop = false;

  // Add the safepoint in the DebugInfoRecorder
  if (sfn->is_MachCall()) {
    MachCallNode* mcall_n = sfn->as_MachCall();

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
  DebugInfo& di = sel->debug_info(sfn);
  GrowableArray<ScopeValue*> *objs = di.objs;

  la_idx = 3;
  youngest_jvms = sfn->jvms();
  int depth = 0, max_depth = youngest_jvms->depth();
  max_spill = 0;
  for (ScopeInfo& si : di.scope_info) {
    depth++;
    jvms = youngest_jvms->of_depth(depth);
    num_mon  = jvms->nof_monitors();
    GrowableArray<ScopeValue*> *locarray = new GrowableArray<ScopeValue*>(si.locs.size());
    for (Node* loc : si.locs) {
      fill_loc_array(locarray, loc);
    }
    GrowableArray<ScopeValue*> *exparray = new GrowableArray<ScopeValue*>(si.exps.size());
    for(Node* exp : si.exps) {
      fill_loc_array(exparray, exp);
    }

    GrowableArray<MonitorValue*> *monarray = new GrowableArray<MonitorValue*>(num_mon);
    for(int idx = 0; idx < num_mon; idx++) {
      // Grab the node that defines this monitor
      Node* box_node = sfn->monitor_box(jvms, idx);
      Node* obj_node = sfn->monitor_obj(jvms, idx);
      bool eliminated = (box_node->is_BoxLock() && box_node->as_BoxLock()->is_eliminated());
      int mon_idx = box_node->as_BoxLock()->stack_slot() / 2;

      int mon_object_offset = calcUnextendedMonObjOffset(mon_idx);

      // Create ScopeValue for object
      ScopeValue *scval = NULL;
      MonitorInfo& mi = si.mons[idx];
      if( obj_node->is_SafePointScalarObject() ) {
        sc_obj = mi.ni->as_sc_obj();
        // here we won't be adding this sc_obj but rather its fields instead
        fill_loc_array(sc_obj->dest, sc_obj->node);
        scval = sc_obj->sc_val;
      } else if( !obj_node->is_Con() ) {
        Location::Type oop_type = obj_node->bottom_type()->base() == Type::NarrowOop ? Location::narrowoop : Location::oop;
        scval = new LocationValue(Location::new_stk_loc(oop_type, mon_object_offset));
      } else {
        const TypePtr *tp = obj_node->bottom_type()->make_ptr();
        scval = new ConstantOopWriteValue(tp->is_oopptr()->const_oop()->constant_encoding());
      }

      Location basic_lock = Location::new_stk_loc(Location::normal, calcUnextendedMonOffset(mon_idx));
      monarray->append(new MonitorValue(scval, basic_lock, eliminated));
      if (!obj_node->is_SafePointScalarObject() && !(eliminated && obj_node->is_Con())) {
        oopmap->set_oop(VMRegImpl::stack2reg(mon_object_offset / wordSize));
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
    C->debug_info()->describe_scope(pc_offset, scope_method, jvms->bci(), jvms->should_reexecute(), is_method_handle_invoke, return_oop, locvals, expvals, monvals);
  }

  C->debug_info()->end_safepoint(pc_offset);
}

DebugInfo ScopeDescriptor::init_debug_info(MachSafePointNode* sfn) {
  DebugInfo di;
  this->sfn = sfn;
  di.sfn_id = sel->debug_info().size();
  youngest_jvms = sfn->jvms();
  objs = new GrowableArray<ScopeValue*>();
  di.objs = objs;
  int max_depth = youngest_jvms->depth();
  for (int depth = 1; depth <= max_depth; depth++) {
    ScopeInfo si;
    jvms = youngest_jvms->of_depth(depth);
    int idx;
    method = jvms->has_method() ? jvms->method() : NULL;
    // Safepoints that do not have method() set only provide oop-map and monitor info
    // to support GC; these do not support deoptimization.
    int num_locs = (method == NULL) ? 0 : jvms->loc_size();
    int num_exps = (method == NULL) ? 0 : jvms->stk_size();
    assert(method == NULL || jvms->bci() < 0 || num_locs == method->max_locals(),
           "JVMS local count must match that of the method");
    // Add Local and Expression Stack Information

    // Insert locals into the locarray
    si.locs.reserve(num_locs);
    si.exps.reserve(num_exps);
    for (idx = 0; idx < num_locs; ++idx) {
      Node* n = sfn->local(jvms, idx);
      si.locs.push_back(n);
    }
    for (idx = 0; idx < num_exps; ++idx) {
      Node* n = sfn->stack(jvms, idx);
      si.exps.push_back(n);
    }
    num_mon = jvms->nof_monitors();
    si.mons.reserve(num_mon);
    assert( !method ||
              !method->is_synchronized() ||
              method->is_native() ||
              num_mon > 0 ||
              !GenerateSynchronizationCode,
              "monitors must always exist for synchronized methods");
    for(idx = 0; idx < num_mon; idx++) {
      MonitorInfo mi;
      Node* obj_node = sfn->monitor_obj(jvms, idx);
      mi.ni = obj_node->is_SafePointScalarObject()
        ? std::make_shared<ScalarObjectInfo>() : std::make_shared<NodeInfo>();
      mi.ni->node = obj_node;
      init_obj_info(mi.ni.get());
      si.mons.push_back(mi);
    }
    di.scope_info.push_back(si);
  }
  return di;
}

void ScopeDescriptor::init_obj_info(NodeInfo* ni) {
  Node* obj_node = ni->node;
  if( !obj_node->is_SafePointScalarObject() ) return;
  sc_obj = ni->as_sc_obj();
  SafePointScalarObjectNode* spobj = obj_node->as_SafePointScalarObject();
  ScopeValue* scval = Compile::sv_for_node_id(objs, spobj->_idx);
  if (scval == NULL) {
    const Type *t = obj_node->bottom_type();
    ciKlass* cik = t->is_oopptr()->klass();
    assert(cik->is_instance_klass() ||
            cik->is_array_klass(), "Not supported allocation.");
    ObjectValue* sv = new ObjectValue(spobj->_idx,
      new ConstantOopWriteValue(cik->java_mirror()->constant_encoding()));
    Compile::set_sv_for_object_node(objs, sv);

    uint first_ind = spobj->first_index(youngest_jvms);
    sc_obj->field_values.reserve(spobj->n_fields());
    sc_obj->dest = sv->field_values();
    for (uint i = 0; i < spobj->n_fields(); i++) {
      std::unique_ptr<NodeInfo> fi = sfn->in(first_ind+i)->is_SafePointScalarObject()
        ? std::make_unique<ScalarObjectInfo>() : std::make_unique<NodeInfo>();
      fi->node = sfn->in(first_ind+i);
      sc_obj->field_values.push_back(std::move(fi));
      init_obj_info(fi.get());
    }
    scval = sv;
  }
  sc_obj->sc_val = scval;
}

llvm::OperandBundleDef ScopeDescriptor::statepoint_scope(MachSafePointNode* sfn) {
  DebugInfo& di = sel->debug_info(sfn);
  std::vector<llvm::Value*> args;
  for (ScopeInfo& si : di.scope_info) {
    for (Node* n : si.locs) {
      args.push_back(sel->select_node_or_const(n));
    }
    for (Node* n : si.exps) {
      args.push_back(sel->select_node_or_const(n));
    }
    for (MonitorInfo& mi : si.mons) {
      auto add_sc_obj = [&](auto&& add_sc_obj, NodeInfo* ni) -> void {
        if (ni->is_sc_obj()) {
          ScalarObjectInfo* sc_obj = ni->as_sc_obj();
          for (std::unique_ptr<NodeInfo>& sc_obj_ni : sc_obj->field_values) {
            add_sc_obj(add_sc_obj, sc_obj_ni.get());
          }
        } else {
          args.push_back(sel->select_node_or_const(ni->node));
        }
      };
      if (mi.ni->is_sc_obj()) {
        add_sc_obj(add_sc_obj, mi.ni.get());
      }
    }
  }
  return llvm::OperandBundleDef("deopt", args);
}

int32_t ScopeDescriptor::calcUnextendedMonOffset(int idx) const {
  return sel->max_stack() * wordSize +
         max_spill +
         (sel->monitors_num() -  idx - 1) * sel->monitor_size();
}

int32_t ScopeDescriptor::calcUnextendedMonObjOffset(int idx) const {
  return calcUnextendedMonOffset(idx) + BasicObjectLock::obj_offset_in_bytes();
}