#pragma once

#include <memory>

namespace ndsec::data {

class DataManager {
public:
  // 数据结构


  virtual ~DataManager() = default;

  /**
   * @brief 应该模板
   * @return
   */
  virtual bool create_table() = 0;

  /**
   * @brief 应该模板
   * @return
   */
  virtual bool empty_table() = 0;

  /**
   * @brief 应该模板
   * @return
   */
  virtual bool check_table() = 0;

  /**
   * @brief 应该模板
   * @return
   */
  virtual bool insert_data() = 0;

  /**
   * @brief 应该模板
   * @return
   */
  virtual bool delete_data() = 0;

  /**
   * @brief 应该模板
   * @return
   */
  virtual bool select_data() = 0;

  virtual uint64_t count() = 0;

  static std::unique_ptr<DataManager> make();
};
} // namespace ndsec::data
