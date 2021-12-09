#include "node_bw_iterator.hpp"

// Constructor for the Node_Backward_Iterator
Node_BW_Iterator::Node_BW_Iterator(Node *root, VectorSet &visited, Node_List &stack, PhaseCFG &cfg)
  : _visited(visited), _stack(stack), _cfg(cfg) {
  // The stack should contain exactly the root
  stack.clear();
  stack.push(root);

  // Clear the visited bits
  visited.Clear();
}

// Iterator for the Node_Backward_Iterator
Node *Node_BW_Iterator::next() {

  // If the _stack is empty, then just return NULL: finished.
  if ( !_stack.size() )
    return NULL;

  // '_stack' is emulating a real _stack.  The 'visit-all-users' loop has been
  // made stateless, so I do not need to record the index 'i' on my _stack.
  // Instead I visit all users each time, scanning for unvisited users.
  // I visit unvisited not-anti-dependence users first, then anti-dependent
  // children next.
  Node *self = _stack.pop();

  assert(self != NULL, "check");
  // I cycle here when I am entering a deeper level of recursion.
  // The key variable 'self' was set prior to jumping here.
  Block* bb = NULL;
  while( 1 ) {

    _visited.set(self->_idx);

    // Now schedule all uses as late as possible.
    const Node* src = self->is_Proj() ? self->in(0) : self;
    bb = _cfg.get_block_for_node(src);
    assert(bb != NULL, "check");
    uint src_rpo = bb->_rpo;

    // Schedule all nodes in a post-order visit
    Node *unvisited = NULL;  // Unvisited anti-dependent Node, if any

    // Scan for unvisited nodes
    for (DUIterator_Fast imax, i = self->fast_outs(imax); i < imax; i++) {
      // For all uses, schedule late
      Node* n = self->fast_out(i); // Use
      assert(n != NULL, "check");

      // Skip already visited children
      if ( _visited.test(n->_idx) )
        continue;

      // do not traverse backward control edges
      Node *use = n->is_Proj() ? n->in(0) : n;
      assert(use != NULL, "check");
      bb = _cfg.get_block_for_node(use);
      assert(bb != NULL, "check");
      uint use_rpo = bb->_rpo;

      if ( use_rpo < src_rpo )
        continue;

      // Phi nodes always precede uses in a basic block
      if ( use_rpo == src_rpo && use->is_Phi() )
        continue;

      unvisited = n;      // Found unvisited

      // Check for possible-anti-dependent
      if( !n->needs_anti_dependence_check() )
        break;            // Not visited, not anti-dep; schedule it NOW
    }

    // Did I find an unvisited not-anti-dependent Node?
    if ( !unvisited )
      break;                  // All done with children; post-visit 'self'

    // Visit the unvisited Node.  Contains the obvious push to
    // indicate I'm entering a deeper level of recursion.  I push the
    // old state onto the _stack and set a new state and loop (recurse).
    _stack.push(self);
    self = unvisited;
  } // End recursion loop

  return self;
}