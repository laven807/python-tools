# pcap文件mac、ip修改工具

- 只支持包含单条流的pcap文件
- 根据首包的mac地址, 判断后续包的方向, 修改对应的mac和ip地址
- 只支持固网包
- 支持ipv4/ipv6/tcp/udp
- 生成的新报文, 会重新计算各个chksum
- 生成的新报文, 按原名保存到 dst_dir 目录下
- 支持ipv4和ipv6互换, 此时只支持结构为 Ether/IP 或 Ether/IPv6 的报文, 且Ether会舍弃原来的, 重新构造