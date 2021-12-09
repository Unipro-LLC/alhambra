#ifndef CPU_LLVM_VM_CODE_GEN_NODE_BW_ITERATOR_HPP
#define CPU_LLVM_VM_CODE_GEN_NODE_BW_ITERATOR_HPP

#include "opto/block.hpp"

class Node_BW_Iterator {

private:
  Node_BW_Iterator();

public:
  // Constructor for the iterator
  Node_BW_Iterator(Node *root, VectorSet &visited, Node_List &stack, PhaseCFG &cfg);

  // Postincrement operator to iterate over the nodes
  Node *next();

private:
  VectorSet   &_visited;
  Node_List   &_stack;
  PhaseCFG    &_cfg;
};

#endif // NODE_BW_ITERATOR_HPP