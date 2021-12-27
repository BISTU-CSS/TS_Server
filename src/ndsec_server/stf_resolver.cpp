#include <iostream>

#include "stf_resolver.h"
#include "time_stamp_server.h"

//处理GRPC任务
namespace ndsec::stf {

// grpc_muti_process

class RpcServer {};

class Resolver {

private:
  std::unique_ptr<time::TimestampServer> time_server_;
};

} // namespace ndsec::stf
