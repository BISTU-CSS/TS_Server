#include "stf_resolver.h"

#include "grpc_cs/greeter_server.h"

using namespace timestamp;


void TimeStampServer::Run() {
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
  std::cout << "Server listening on " << server_address << std::endl;

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

  void* tag;  // uniquely identifies a request.
  bool ok;
  while (true) {
    // Block waiting to read the next event from the completion queue. The
    // event is uniquely identified by its tag, which in this case is the
    // memory address of a CallData instance.
    // The return value of Next should always be checked. This return value
    // tells us whether there is any kind of event or cq_ is shutting down.
    GPR_ASSERT(cq_->Next(&tag, &ok));
    GPR_ASSERT(ok);
    static_cast<CallDataBase*>(tag)->Proceed();
  }
}


void InitEnvironmentCall::Proceed()
{
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
    //reply_.set_message(prefix + request_.name());

    timestamp::Handle *handle = new timestamp::Handle;

    handle->set_session_id(18);
    reply_.set_code(ResponseStatus_MIN);
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

void ClearEnvironmentCall::Proceed()
{
  if (status_ == CREATE) {
    // Make this instance progress to the PROCESS state.
    status_ = PROCESS;

    service_->RequestClearEnvironment(&ctx_, &request_, &responder_, cq_, cq_,
                                          this);
  } else if (status_ == PROCESS) {
    new ClearEnvironmentCall(service_, cq_);

    //TODO
    // The actual processing.
    //std::string prefix("Hello ");
    //reply_.set_message(prefix + request_.name());

    //timestamp::Status *ts_status = new timestamp::Status;

    //reply_.set_allocated_status(ts_status);
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

void CreateTSRequestCall::Proceed()
{
  if (status_ == CREATE) {
    // Make this instance progress to the PROCESS state.
    status_ = PROCESS;

    service_->RequestCreateTSRequest(&ctx_, &request_, &responder_, cq_, cq_,
                                         this);
  } else if (status_ == PROCESS) {
    new CreateTSRequestCall(service_, cq_);

    //TODO
    // The actual processing.
    //std::string prefix("Hello ");
    //reply_.set_message(prefix + request_.name());

    //timestamp::Status *ts_status = new timestamp::Status;

    //reply_.set_allocated_status(ts_status);
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

void CreateTSResponseCall::Proceed()
{
  if (status_ == CREATE) {
    // Make this instance progress to the PROCESS state.
    status_ = PROCESS;

    service_->RequestCreateTSResponse(&ctx_, &request_, &responder_, cq_, cq_,
                                          this);
  } else if (status_ == PROCESS) {
    new CreateTSResponseCall(service_, cq_);

    //TODO
    // The actual processing.
    //std::string prefix("Hello ");
    //reply_.set_message(prefix + request_.name());

    //timestamp::Status *ts_status = new timestamp::Status;

    //reply_.set_allocated_status(ts_status);
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

void VerifyTSValidityCall::Proceed()
{
  if (status_ == CREATE) {
    // Make this instance progress to the PROCESS state.
    status_ = PROCESS;

    service_->RequestVerifyTSValidity(&ctx_, &request_, &responder_, cq_, cq_,
                                          this);
  } else if (status_ == PROCESS) {
    new VerifyTSValidityCall(service_, cq_);

    //TODO
    // The actual processing.
    //std::string prefix("Hello ");
    //reply_.set_message(prefix + request_.name());

    //timestamp::Status *ts_status = new timestamp::Status;

    //reply_.set_allocated_status(ts_status);
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

void GetTSInfoCall::Proceed()
{
  if (status_ == CREATE) {
    // Make this instance progress to the PROCESS state.
    status_ = PROCESS;

    service_->RequestGetTSInfo(&ctx_, &request_, &responder_, cq_, cq_,
                                   this);
  } else if (status_ == PROCESS) {
    new GetTSInfoCall(service_, cq_);

    //TODO
    // The actual processing.
    //std::string prefix("Hello ");
    //reply_.set_message(prefix + request_.name());

    //timestamp::Status *ts_status = new timestamp::Status;

    //reply_.set_allocated_status(ts_status);
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

void GetTSDetailCall::Proceed()
{
  if (status_ == CREATE) {
    // Make this instance progress to the PROCESS state.
    status_ = PROCESS;

    service_->RequestGetTSDetail(&ctx_, &request_, &responder_, cq_, cq_,
                                     this);
  } else if (status_ == PROCESS) {
    new GetTSDetailCall(service_, cq_);

    //TODO
    // The actual processing.
    //std::string prefix("Hello ");
    //reply_.set_message(prefix + request_.name());

    //timestamp::Status *ts_status = new timestamp::Status;

    //reply_.set_allocated_status(ts_status);
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
