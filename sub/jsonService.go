package sub

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/service"
	"github.com/alireza0/s-ui/util"
)

const defaultJson = `
{
  "inbounds": [
    {
      "type": "tun",
      "address": [
				"172.19.0.1/30",
				"fdfe:dcba:9876::1/126"
			],
      "mtu": 9000,
      "auto_route": true,
      "strict_route": false,
      "endpoint_independent_nat": false,
      "stack": "system",
      "platform": {
        "http_proxy": {
          "enabled": true,
          "server": "127.0.0.1",
          "server_port": 2080
        }
      }
    },
    {
      "type": "mixed",
      "listen": "127.0.0.1",
      "listen_port": 2080,
      "users": []
    }
  ]
}
`

type JsonService struct {
	service.SettingService
	LinkService
}

func (j *JsonService) GetJson(subId string, format string) (*string, []string, error) {
	var jsonConfig map[string]interface{}

	client, inDatas, err := j.getData(subId)
	if err != nil {
		return nil, nil, err
	}

	outbounds, outTags, err := j.getOutbounds(client.Config, inDatas)
	if err != nil {
		return nil, nil, err
	}

	extOutbounds, extTags := j.LinkService.GetExternalOutbounds(&client.Links)
	*outbounds = append(*outbounds, extOutbounds...)
	*outTags = append(*outTags, extTags...)

	j.addDefaultOutbounds(outbounds, outTags)

	err = json.Unmarshal([]byte(defaultJson), &jsonConfig)
	if err != nil {
		return nil, nil, err
	}

	jsonConfig["outbounds"] = outbounds

	// Add other objects from settings
	j.addOthers(&jsonConfig)

	result, _ := json.MarshalIndent(jsonConfig, "", "  ")
	resultStr := string(result)

	updateInterval, _ := j.SettingService.GetSubUpdates()
	headers := util.GetHeaders(client, updateInterval)

	return &resultStr, headers, nil
}

func (j *JsonService) getData(subId string) (*model.Client, []*model.Inbound, error) {
	db := database.GetDB()
	client := &model.Client{}
	err := db.Model(model.Client{}).Where("enable = true and name = ?", subId).First(client).Error
	if err != nil {
		return nil, nil, err
	}
	var clientInbounds []uint
	err = json.Unmarshal(client.Inbounds, &clientInbounds)
	if err != nil {
		return nil, nil, err
	}
	var inbounds []*model.Inbound
	err = db.Model(model.Inbound{}).Preload("Tls").Where("id in ?", clientInbounds).Find(&inbounds).Error
	if err != nil {
		return nil, nil, err
	}
	return client, inbounds, nil
}

// shouldKeepVLESSVisionFlow 判断当前 inbound 在生成 JSON / Clash 订阅出站时，
// 是否应该保留 VLESS 的 xtls-rprx-vision flow。
//
// 背景说明：
//  1. Clash 订阅中的 proxies 数据来自 JsonService.getOutbounds；
//  2. 如果这里提前把 flow 删除，后面的 ClashService 即使支持输出 flow，也拿不到 flow；
//  3. 旧逻辑使用 bytes.Contains(inData.Options, []byte(`"transport"`)) 判断是否删除 flow；
//  4. 这种判断会把 transport:{} 误判为非 TCP，导致 Reality Vision 节点缺少 flow；
//  5. 正确逻辑应该参考 s-ui-x：只有 transport.type 明确不是 tcp 时，才剥离 flow。
//
// 保留 flow 的条件：
//  1. 协议必须是 vless；
//  2. inbound 必须启用 TLS / REALITY，即 inData.TlsId > 0；
//  3. transport 必须是 TCP，或者未显式配置 transport，或者 transport:{}。
//
// 删除 flow 的条件：
//  1. 非 vless 协议；
//  2. 没有 TLS / REALITY；
//  3. transport.type 明确是 ws / grpc / http / httpupgrade 等非 TCP 类型；
//  4. Options JSON 解析失败，为避免生成非法配置，保守删除 flow。
//
// s-ui-x 的修复思路是（https://github.com/deposist/s-ui-x/commit/d3452529165ed035f1116513f9a07abda72ac73a)：
// - transport 不存在或 type 为空：不剥离 flow；
// - transport.type 明确存在且不是 tcp：剥离 flow；
// - 无 TLS：剥离 flow。
func shouldKeepVLESSVisionFlow(protocol string, inData *model.Inbound) bool {
	if protocol != "vless" || inData == nil {
		return false
	}

	// xtls-rprx-vision 必须配合 TLS / REALITY 使用。
	// 没有 TLS 的 VLESS 不应该携带 flow。
	if inData.TlsId == 0 {
		return false
	}

	var options map[string]interface{}
	if err := json.Unmarshal(inData.Options, &options); err != nil {
		// Options 解析失败时保守处理：不保留 flow。
		// 这样可以避免生成一个可能被客户端或 Xray-core 拒绝的订阅配置。
		return false
	}

	// 关键点：
	//   不要再通过 “是否存在 transport 字符串” 判断是否删除 flow。
	//
	// 原因：
	//   transport:{} 是前端 / 默认配置中很常见的空对象，
	//   它并不代表 WebSocket / gRPC / HTTPUpgrade 等非 TCP 传输。
	//
	// util.IsTCPTransport 的规则和 s-ui-x 修复思路保持一致：
	//   - transport 不存在：TCP
	//   - transport:{}：TCP
	//   - transport.type 为空：TCP
	//   - transport.type == tcp：TCP
	//   - transport.type == ws/grpc/http/httpupgrade：非 TCP
	return util.IsTCPTransport(options["transport"])
}

func (j *JsonService) getOutbounds(clientConfig json.RawMessage, inbounds []*model.Inbound) (*[]map[string]interface{}, *[]string, error) {
	var outbounds []map[string]interface{}
	var configs map[string]interface{}
	var outTags []string

	err := json.Unmarshal(clientConfig, &configs)
	if err != nil {
		return nil, nil, err
	}
	for _, inData := range inbounds {
		if len(inData.OutJson) < 5 {
			continue
		}
		var outbound map[string]interface{}
		err = json.Unmarshal(inData.OutJson, &outbound)
		if err != nil {
			return nil, nil, err
		}
		protocol, _ := outbound["type"].(string)

		// Shadowsocks
		if protocol == "shadowsocks" {
			var userPass []string
			var inbOptions map[string]interface{}
			err = json.Unmarshal(inData.Options, &inbOptions)
			if err != nil {
				return nil, nil, err
			}
			method, _ := inbOptions["method"].(string)
			if strings.HasPrefix(method, "2022") {
				inbPass, _ := inbOptions["password"].(string)
				userPass = append(userPass, inbPass)
			}
			var pass string
			if method == "2022-blake3-aes-128-gcm" {
				pass, _ = configs["shadowsocks16"].(map[string]interface{})["password"].(string)
			} else {
				pass, _ = configs["shadowsocks"].(map[string]interface{})["password"].(string)
			}
			userPass = append(userPass, pass)
			outbound["password"] = strings.Join(userPass, ":")
		} else { // Other protocols
			config, _ := configs[protocol].(map[string]interface{})
			for key, value := range config {
				if key == "name" || key == "alterId" {
					continue
				}
				if key == "flow" {
					//if inData.TlsId == 0 || bytes.Contains(inData.Options, []byte(`"transport"`)) {
					//	continue
					//}

					// VLESS flow 不能简单根据 Options 中是否出现 "transport" 字符串来删除。
					//
					// 旧逻辑问题：
					//   if inData.TlsId == 0 || bytes.Contains(inData.Options, []byte(`"transport"`)) {
					//       continue
					//   }
					//
					// 这会把 transport:{} 这种默认空对象误判为非 TCP，
					// 导致 Clash / JSON 订阅缺少：
					//
					//   flow: xtls-rprx-vision
					//
					// 新逻辑参考 s-ui-x（https://github.com/deposist/s-ui-x/commit/d3452529165ed035f1116513f9a07abda72ac73a)）：
					//   - VLESS + TLS/REALITY + TCP：保留 flow；
					//   - VLESS + TLS/REALITY + transport:{}：保留 flow；
					//   - VLESS + ws/grpc/http/httpupgrade：删除 flow；
					//   - VLESS + 无 TLS：删除 flow。
					if !shouldKeepVLESSVisionFlow(protocol, inData) {
						continue
					}
				}
				outbound[key] = value
			}
		}

		var addrs []map[string]interface{}
		err = json.Unmarshal(inData.Addrs, &addrs)
		if err != nil {
			return nil, nil, err
		}
		tag, _ := outbound["tag"].(string)
		if len(addrs) == 0 {
			// For mixed protocol, use separated socks and http
			if protocol == "mixed" {
				outbound["tag"] = tag
				j.pushMixed(&outbounds, &outTags, outbound)
			} else {
				outTags = append(outTags, tag)
				outbounds = append(outbounds, outbound)
			}
		} else {
			for index, addr := range addrs {
				// Copy original config
				newOut := make(map[string]interface{}, len(outbound))
				for key, value := range outbound {
					newOut[key] = value
				}
				// Change and push copied config
				newOut["server"], _ = addr["server"].(string)
				port, _ := addr["server_port"].(float64)
				newOut["server_port"] = int(port)

				// Override TLS
				if addrTls, ok := addr["tls"].(map[string]interface{}); ok {
					outTls, _ := newOut["tls"].(map[string]interface{})
					if outTls == nil {
						outTls = make(map[string]interface{})
					}
					for key, value := range addrTls {
						outTls[key] = value
					}
					newOut["tls"] = outTls
				}

				remark, _ := addr["remark"].(string)
				newTag := fmt.Sprintf("%d.%s%s", index+1, tag, remark)
				newOut["tag"] = newTag
				// For mixed protocol, use separated socks and http
				if protocol == "mixed" {
					j.pushMixed(&outbounds, &outTags, newOut)
				} else {
					outTags = append(outTags, newTag)
					outbounds = append(outbounds, newOut)
				}
			}
		}
	}
	return &outbounds, &outTags, nil
}

func (j *JsonService) addDefaultOutbounds(outbounds *[]map[string]interface{}, outTags *[]string) {
	outbound := []map[string]interface{}{
		{
			"outbounds": append([]string{"auto", "direct"}, *outTags...),
			"tag":       "proxy",
			"type":      "selector",
		},
		{
			"tag":       "auto",
			"type":      "urltest",
			"outbounds": outTags,
			"url":       "http://www.gstatic.com/generate_204",
			"interval":  "10m",
			"tolerance": 50,
		},
		{
			"type": "direct",
			"tag":  "direct",
		},
	}
	*outbounds = append(outbound, *outbounds...)
}

func (j *JsonService) addOthers(jsonConfig *map[string]interface{}) error {
	// Default routing rules, used only when the template doesn't define its own.
	// When the template provides `rules`, they are used verbatim so the user has
	// full control over ordering (e.g. rules before sniff) and which rules exist.
	defaultRules := []interface{}{
		map[string]interface{}{
			"action": "sniff",
		},
		map[string]interface{}{
			"clash_mode": "Direct",
			"action":     "route",
			"outbound":   "direct",
		},
		map[string]interface{}{
			"clash_mode": "Global",
			"action":     "route",
			"outbound":   "proxy",
		},
	}
	route := map[string]interface{}{
		"auto_detect_interface": true,
		"final":                 "proxy",
		"rules":                 defaultRules,
	}

	othersStr, err := j.SettingService.GetSubJsonExt()
	if err != nil {
		return err
	}
	if len(othersStr) == 0 {
		(*jsonConfig)["route"] = route
		return nil
	}
	var othersJson map[string]interface{}
	err = json.Unmarshal([]byte(othersStr), &othersJson)
	if err != nil {
		return err
	}
	if _, ok := othersJson["log"]; ok {
		(*jsonConfig)["log"] = othersJson["log"]
	}
	if _, ok := othersJson["dns"]; ok {
		(*jsonConfig)["dns"] = othersJson["dns"]
	}
	if _, ok := othersJson["inbounds"]; ok {
		(*jsonConfig)["inbounds"] = othersJson["inbounds"]
	}
	if _, ok := othersJson["experimental"]; ok {
		(*jsonConfig)["experimental"] = othersJson["experimental"]
	}
	if _, ok := othersJson["rule_set"]; ok {
		route["rule_set"] = othersJson["rule_set"]
	}
	if settingRules, ok := othersJson["rules"].([]interface{}); ok {
		route["rules"] = settingRules
	}
	if defaultDomainResolver, ok := othersJson["default_domain_resolver"].(string); ok {
		route["default_domain_resolver"] = defaultDomainResolver
	}
	if v, ok := othersJson["override_android_vpn"]; ok {
		route["override_android_vpn"] = v
	}
	if final, ok := othersJson["final"].(string); ok && final != "" {
		route["final"] = final
	}
	(*jsonConfig)["route"] = route

	return nil
}

func (j *JsonService) pushMixed(outbounds *[]map[string]interface{}, outTags *[]string, out map[string]interface{}) {
	socksOut := make(map[string]interface{}, 1)
	httpOut := make(map[string]interface{}, 1)
	for key, value := range out {
		socksOut[key] = value
		httpOut[key] = value
	}
	socksTag := fmt.Sprintf("%s-socks", out["tag"])
	httpTag := fmt.Sprintf("%s-http", out["tag"])
	socksOut["type"] = "socks"
	httpOut["type"] = "http"
	socksOut["tag"] = socksTag
	httpOut["tag"] = httpTag
	*outbounds = append(*outbounds, socksOut, httpOut)
	*outTags = append(*outTags, socksTag, httpTag)
}
