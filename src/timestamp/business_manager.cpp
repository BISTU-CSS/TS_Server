#include "business_manager.h"

namespace ndsec::business {

class BusinessManagerImpl : public BusinessManager{
public:

};

std::unique_ptr<BusinessManager> BusinessManager::make() {
  return std::make_unique<BusinessManagerImpl>();
}

}