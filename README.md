聊天室

2xx 指令执行成功
3xx 权限被拒绝
4xx 指令语法错误, 执行失败
5xx 服务器错误

SIGN_UP username password
200 user_id role message

SIGN_IN username password
200 token message

SIGN_OUT 
200 message

LIST_ROOM 
200 message
roomid1 roomname1
roomid2 roomname2

ENTER_ROOM  roomid
200 message

EXIT_ROOM 
200 message

CREATE_ROOM  roomname limit

DELETE_ROOM  roomid