#include "grpc_cs/greeter_server.h"

int main() {
  TimeStampServer service;
  service.Run();
  return 0;
}
