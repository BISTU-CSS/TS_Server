#include "grpc_cs/greeter_server.h"

#include "data_manager.h"
#include "ndsec_ts_error.h"
#include "session_manager.h"
#include "timestamp_manager.h"

#include "openssl/ts.h"

std::unique_ptr<ndsec::stf::session::SessionManager> session_pool;
std::unique_ptr<ndsec::timetool::TimeManager> time_manager;
std::unique_ptr<ndsec::data::DataManager> data_manager;

void TimeStampServer::Run() {
  // init system
  session_pool = ndsec::stf::session::SessionManager::make();
  time_manager = ndsec::timetool::TimeManager::make();
  data_manager = ndsec::data::DataManager::make();

  data_manager->init_db();

  std::string server_address("0.0.0.0:50051");

  grpc::ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  // Register "service_" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *asynchronous* service.
  builder.RegisterService(&service_);
  // Get hold of the completion queue used for the asynchronous communication
  // with the gRPC runtime.
  cq_ = builder.AddCompletionQueue();
  // Finally assemble the server.
  server_ = builder.BuildAndStart();

  // Proceed to the server's main loop.
  HandleRpcs();
}

void TimeStampServer::HandleRpcs() {
  // Spawn a new CallData instance to serve new clients.
  new InitEnvironmentCall(&service_, cq_.get());
  new ClearEnvironmentCall(&service_, cq_.get());
  new CreateTSRequestCall(&service_, cq_.get());
  new CreateTSResponseCall(&service_, cq_.get());
  new VerifyTSValidityCall(&service_, cq_.get());
  new GetTSInfoCall(&service_, cq_.get());
  new GetTSDetailCall(&service_, cq_.get());

  void *tag; // uniquely identifies a request.
  bool ok;
  while (true) {
    // Block waiting to read the next event from the completion queue. The
    // event is uniquely identified by its tag, which in this case is the
    // memory address of a CallData instance.
    // The return value of Next should always be checked. This return value
    // tells us whether there is any kind of event or cq_ is shutting down.
    GPR_ASSERT(cq_->Next(&tag, &ok));
    GPR_ASSERT(ok);
    static_cast<CallDataBase *>(tag)->Proceed();
  }
}

void InitEnvironmentCall::Proceed() {
  if (status_ == CREATE) {
    // Make this instance progress to the PROCESS state.
    status_ = PROCESS;

    // As part of the initial CREATE state, we *request* that the system
    // start processing SayHello requests. In this request, "this" acts are
    // the tag uniquely identifying the request (so that different CallData
    // instances can serve different requests concurrently), in this case
    // the memory address of this CallData instance.
    service_->RequestInitEnvironment(&ctx_, &request_, &responder_, cq_, cq_,
                                     this);
  } else if (status_ == PROCESS) {
    // Spawn a new CallData instance to serve new clients while we process
    // the one for this CallData. The instance will deallocate itself as
    // part of its FINISH state.
    // new HelloCall(service_, cq_);
    // new CallData(service_, cq_);
    new InitEnvironmentCall(service_, cq_);

    // The actual processing.
    // reply_.set_message(prefix + request_.name());

    auto *handle = new timestamp::Handle;
    uint64_t a = session_pool->get_session();
    handle->set_session_id(a);

    std::cout << a << std::endl;

    reply_.set_code(timestamp::GRPC_STF_TS_OK);
    reply_.set_allocated_handle(handle);

    // And we are done! Let the gRPC runtime know we've finished, using the
    // memory address of this instance as the uniquely identifying tag for
    // the event.
    status_ = FINISH;
    responder_.Finish(reply_, grpc::Status::OK, this);
  } else {
    GPR_ASSERT(status_ == FINISH);
    // Once in the FINISH state, deallocate ourselves (CallData).
    delete this;
  }
}

void ClearEnvironmentCall::Proceed() {
  if (status_ == CREATE) {
    status_ = PROCESS;
    service_->RequestClearEnvironment(&ctx_, &request_, &responder_, cq_, cq_,
                                      this);
  } else if (status_ == PROCESS) {
    new ClearEnvironmentCall(service_, cq_);
    uint64_t session_handle = request_.handle().session_id();
    if (session_pool->is_session_exist(session_handle)) {
      session_pool->free_session(session_handle);
      reply_.set_code(timestamp::GRPC_STF_TS_OK);
    } else {
      reply_.set_code(timestamp::GRPC_STF_TS_INVALID_REQUEST); //非法的申请
    }
    status_ = FINISH;
    responder_.Finish(reply_, grpc::Status::OK, this);
  } else {
    GPR_ASSERT(status_ == FINISH);
    delete this;
  }
}

void CreateTSRequestCall::Proceed() {
  if (status_ == CREATE) {
    status_ = PROCESS;
    service_->RequestCreateTSRequest(&ctx_, &request_, &responder_, cq_, cq_,
                                     this);
  } else if (status_ == PROCESS) {
    new CreateTSRequestCall(service_, cq_);
    uint64_t session_handle = request_.handle().session_id();
    if (session_pool->is_session_exist(session_handle)) {
      // session存在
      // 创建结构体
      std::cout << ctx_.peer() << std::endl;
      // std::cout<<ctx_.client_metadata().find("x-real-ip")->first<<std::endl;
      //获取包内变量设置
      request_.uihashalgid();    //算法标识
      request_.pucindata();      //加盖时间戳的用户信息
      request_.uiindatalength(); //加盖时间戳的用户信息长度

      //证书设置
      if (request_.uireqtype() == 0) {
        //包含时间戳服务器的证书

      } else if (request_.uireqtype() == 1) {
        //不包含时间戳服务器的证书

      } else {
        reply_.set_code(timestamp::GRPC_STF_TS_INVALID_REQUEST); //非法的申请
      }

      std::string package = "dsadsa";
      reply_.set_puctsrequest(package);
      reply_.set_puctsrequestlength(package.length());
      reply_.set_code(timestamp::GRPC_STF_TS_OK);
    } else {
      reply_.set_code(timestamp::GRPC_STF_TS_INVALID_REQUEST); //非法的申请
    }
    status_ = FINISH;
    responder_.Finish(reply_, grpc::Status::OK, this);
  } else {
    GPR_ASSERT(status_ == FINISH);
    delete this;
  }
}

void CreateTSResponseCall::Proceed() {
  if (status_ == CREATE) {
    status_ = PROCESS;
    service_->RequestCreateTSResponse(&ctx_, &request_, &responder_, cq_, cq_,
                                      this);
  } else if (status_ == PROCESS) {
    new CreateTSResponseCall(service_, cq_);
    uint64_t session_handle = request_.handle().session_id();
    if (session_pool->is_session_exist(session_handle)) {
      // session存在

      //结构体

      //获取包内变量设置
      request_.uisignaturealgid();  //签名算法标识
      request_.puctsresquest();     //时间戳请求包
      request_.uitsrequestlength(); //时间戳请求包长度

      std::string package = "dsadsa"; //结构体转换为string
      reply_.set_puitsresponse(package);
      reply_.set_puitsresponselength(package.length());

      if (request_.uisignaturealgid() == SGD_SHA1) {
        std::string time = time_manager->get_time();
        // reply_.set_puitsresponse();
        // reply_.set_puitsresponselength();
      } else if (request_.uisignaturealgid() == SGD_SHA256) {
        std::string time = time_manager->get_time();
        // reply_.set_puitsresponse();
        // reply_.set_puitsresponselength();
      } else if (request_.uisignaturealgid() == SGD_SM3) {

        std::string time = time_manager->get_time();
        // reply_.set_puitsresponse();
        // reply_.set_puitsresponselength();
        reply_.set_code(timestamp::GRPC_STF_TS_OK);
      } else {
        reply_.set_code(timestamp::GRPC_STF_TS_INVALID_ALG); //不支持的算法类型
      }

    } else {
      reply_.set_code(timestamp::GRPC_STF_TS_INVALID_REQUEST); //非法的申请
    }
    status_ = FINISH;
    responder_.Finish(reply_, grpc::Status::OK, this);
  } else {
    GPR_ASSERT(status_ == FINISH);
    delete this;
  }
}

void VerifyTSValidityCall::Proceed() {
  if (status_ == CREATE) {
    status_ = PROCESS;
    service_->RequestVerifyTSValidity(&ctx_, &request_, &responder_, cq_, cq_,
                                      this);
  } else if (status_ == PROCESS) {
    new VerifyTSValidityCall(service_, cq_);
    uint64_t session_handle = request_.handle().session_id();
    if (session_pool->is_session_exist(session_handle)) {
      // session存在

      reply_.set_code(timestamp::GRPC_STF_TS_OK);
    } else {
      reply_.set_code(timestamp::GRPC_STF_TS_INVALID_REQUEST); //非法的申请
    }
    status_ = FINISH;
    responder_.Finish(reply_, grpc::Status::OK, this);
  } else {
    GPR_ASSERT(status_ == FINISH);
    delete this;
  }
}

void GetTSInfoCall::Proceed() {
  if (status_ == CREATE) {
    status_ = PROCESS;

    service_->RequestGetTSInfo(&ctx_, &request_, &responder_, cq_, cq_, this);
  } else if (status_ == PROCESS) {
    new GetTSInfoCall(service_, cq_);
    uint64_t session_handle = request_.handle().session_id();
    if (session_pool->is_session_exist(session_handle)) {
      // session存在
      auto *TSA_ISSUENAME = (std::string *)"NDSEC_TSA";

      reply_.set_allocated_pucissuername(TSA_ISSUENAME);

      reply_.set_code(timestamp::GRPC_STF_TS_OK);
    } else {
      reply_.set_code(timestamp::GRPC_STF_TS_INVALID_REQUEST); //非法的申请
    }
    status_ = FINISH;
    responder_.Finish(reply_, grpc::Status::OK, this);
  } else {
    GPR_ASSERT(status_ == FINISH);
    delete this;
  }
}

void GetTSDetailCall::Proceed() {
  if (status_ == CREATE) {
    status_ = PROCESS;
    service_->RequestGetTSDetail(&ctx_, &request_, &responder_, cq_, cq_, this);
  } else if (status_ == PROCESS) {
    new GetTSDetailCall(service_, cq_);
    uint64_t session_handle = request_.handle().session_id();
    if (session_pool->is_session_exist(session_handle)) {
      // session存在

      reply_.set_code(timestamp::GRPC_STF_TS_OK);
    } else {
      reply_.set_code(timestamp::GRPC_STF_TS_INVALID_REQUEST); //非法的申请
    }
    status_ = FINISH;
    responder_.Finish(reply_, grpc::Status::OK, this);
  } else {
    GPR_ASSERT(status_ == FINISH);
    delete this;
  }
}
