#pragma once

// 系统内部错误码,采用4位16进制,即16bit(2Byte)表示错误信息
namespace ndsec::timetool::error {

#define NDSEC_SYS_OK 0x0000
#define BEIDOUSYS_ERROR 0x0001
#define TIMETYPE_ERROR 0x0002

} // namespace ndsec::timetool::error
