//
// Created by dx on 2022/1/25.
//
#include <iostream>
#include "grpc_cs/greeter_server.h"
using namespace  std;
int main() {
  TimeStampServer service;

  service.Run();

  return 0;
}