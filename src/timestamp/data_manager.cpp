#include "data_manager.h"

namespace ndsec::data {

class DataManagerImpl : public DataManager {
public:
};

std::unique_ptr<DataManager> DataManager::make() {

  return std::make_unique<DataManagerImpl>();
}

} // namespace ndsec::data
