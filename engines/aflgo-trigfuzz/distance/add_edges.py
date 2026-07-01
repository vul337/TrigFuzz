#!/usr/bin/env python3

import argparse
import networkx as nx

class AddEdge:

  def run(self) -> None:
    parser = argparse.ArgumentParser()    
    parser.add_argument('-d', '--dot',         type=str, required=True, help="Path to dot-file representing the graph")
    parser.add_argument('-e', '--extra_edges', type=str, required=True, help="Extra edges to add to graph")
    args = parser.parse_args()

    print("\nParsing %s .." % args.dot)
    self.G = nx.Graph(nx.drawing.nx_pydot.read_dot(args.dot))
    print(nx.info(self.G))

    self.is_cg = 1 if "Name: Call graph" in nx.info(self.G) else 0
    print("\nWorking in %s mode.." % ("CG" if self.is_cg else "CFG"))

    before = nx.number_connected_components(self.G)
    print("Adding edges..")

    self.was_added = 0
    with open(args.extra_edges, "r") as f:
      map(self.parse_edges, f.readlines())

    print("\n############################################")
    print("#Connected components reduced from %d to %d." % (before, nx.number_connected_components(self.G)))
    print("############################################")

    print("\nWriting %s .." % args.dot)
    if self.was_added:
      nx.drawing.nx_pydot.write_dot(self.G, args.dot)

  def node_name(self, name):
    if self.is_cg:
      return "\"{%s}\"" % name
    else:
      return "\"{%s:" % name

  def parse_edges(self, line):
    edges = line.split()

    n1_name = self.node_name(edges[0])
    n1_list = list(filter(
      lambda node: ('label' in node[1]) and (n1_name in node[1]['label']), 
      self.G.nodes(data=True)
    ))

    if len (n1_list) > 0:
        (n1, _) = n1_list[0]

        for i in range (2, len(edges)):

          n2_name = self.node_name(edges[i])
          n2_list = list(filter(
            lambda node: 'label' in node[1] and n2_name in node[1]['label'],
            self.G.nodes(data=True)
          ))

          if len (n2_list) > 0:
            (n2, _) = n2_list[0]

            if self.G.has_edge(n1, n2):
              print("[x] %s -> %s" % (n1_name, n2_name))
            else:
              print("[v] %s -> %s" % (n1_name, n2_name))
              self.G.add_edge(n1,n2)
              self.was_added = 1
    #else:
    #  print("Could not find %s" % n1_name)

# Main function
if __name__ == '__main__':
  AddEdge().run()
