package util

// IsTCPTransport 判断一个 inbound / outbound transport 配置是否应当视为 TCP。
//
// 这个函数主要用于判断 VLESS 的 xtls-rprx-vision flow 是否可以保留。
//
// 背景说明：
//  1. xtls-rprx-vision 只适用于 VLESS + TCP + TLS/REALITY；
//  2. 对于 ws / grpc / http / httpupgrade 等非 TCP 传输，不能携带该 flow；
//  3. 旧逻辑常见写法是：只要 options 里出现 "transport" 字段就删除 flow；
//  4. 但新版前端 / 默认配置里可能出现 transport:{} 这种空对象；
//  5. transport:{} 并不代表非 TCP，它应该按默认 TCP 处理。
//
// 判断规则：
//  1. transport 不存在，默认视为 TCP；
//  2. transport 不是 map，默认视为 TCP；
//  3. transport:{}，默认视为 TCP；
//  4. transport.type 为空，默认视为 TCP；
//  5. transport.type == "tcp"，视为 TCP；
//  6. transport.type == "ws" / "grpc" / "http" / "httpupgrade" 等，视为非 TCP。
func IsTCPTransport(t interface{}) bool {
	transport, ok := t.(map[string]interface{})
	if !ok {
		// 没有 transport，或者 transport 结构不是 map。
		// 对 S-UI / sing-box / Xray 的默认语义来说，没有显式 transport 通常就是 TCP。
		return true
	}

	transportType, _ := transport["type"].(string)
	if transportType == "" {
		// transport:{} 或 transport.type 为空。
		// 这类情况不能当成 ws/grpc/http 等非 TCP，否则会误删 Reality Vision flow。
		return true
	}

	return transportType == "tcp"
}
