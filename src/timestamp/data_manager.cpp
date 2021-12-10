#include "data_manager.h"

namespace ndsec::data {


std::unique_ptr<DataManager> DataManager::make() {

  return std::make_unique<DataManager>();
}


}