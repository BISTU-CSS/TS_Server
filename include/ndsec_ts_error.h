#pragma once

namespace ndsec::timetool::error {

#define STF_TS_OK 0 //正常返回
#define STF_TS_ERROR_BASE 0x04000000
#define STF_TS_INDATA_TOOLONG 0x04000001 //输入的用户信息超出规定范围   client
#define STF_TS_NOT_ENOUGH_MEMORY 0x04000002 //分配给tsrequest的内存空间不够  client
#define STF_TS_SERVER_ERROR 0x04000003      //找不到服务器或超时响应   client
#define STF_TS_MALFORMAT 0x04000004         //时间戳格式错误
#define STF_TS_INVALID_ITEM 0x04000005      //输人项目编号无效
#define STF_TS_INVALID_SIGNATURE 0x04000006 //签名无效
#define STF_TS_INVALID_ALG 0x04000007       //申请使用了不支持的算法
#define STF_TS_INVALID_REQUEST 0x04000008   //非法的申请
#define STF_TS_INVALID_DATAFORMAT 0x04000009 //数据格式错误
#define STF_TS_TIME_NOT_AVAILABLE 0x0400000A //TSA的可信时间源出现问题
#define STF_TS_UNACCEPTED_POLICY 0x0400000B //不支持申请消息中声明的策略
#define STF_TS_UNACCEPTED_EXTENSION 0x0400000C //申请消息中包括了不支持的扩展
#define STF_TS_ADDINFO_NOT_AVAILBLE 0x0400000D //有不理解或不可用的附加信息
#define STF_TS_SYSTEM_FAILURE 0x0400000E //系统内部错误

} // namespace ndsec::timetool::error
