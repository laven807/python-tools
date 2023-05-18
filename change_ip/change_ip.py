#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
Author       : zouxuan
Date         : 2023-05-18 10:17:37
LastEditTime : 2023-05-18 17:30:32
LastEditors  : zouxuan
Description  :
FilePath     : change_ip.py
'''

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
import os
from rich import print
from rich.markup import escape
import posixpath


def get_file_list():
    def _get_file_list(file_path):
        file_list = []
        for root, dirs, files in os.walk(file_path):
            files = [f for f in files if not f[0] == '.']
            for name in files:
                # file_list.append(os.path.join(root, name))
                file_list.append(os.path.abspath(os.path.join(root, name)))
            # break
        try:
            file_list = sorted(file_list, key=lambda i: int(re.findall(r'_stream(\d*?)_', i)[0]))
        except:
            file_list.sort()
        return file_list

    file_list = []
    file_name = args['file']
    if os.path.isdir(file_name):
        file_list = _get_file_list(file_name)
    else:
        file_list.append(file_name)
    return file_list


def change_pcap(file_list, five_tuple, dst_dir):
    """
    - 根据首包的mac地址, 判断后续包的方向, 修改对应的mac和ip地址
    - 只支持固网包
    - 支持ipv4/ipv6/tcp/udp
    - 生成的新报文, 会重新计算各个chksum


    Args:
        file_list (_type_): _description_
        five_tuple (_type_): _description_
        dst_dir (_type_): _description_
    """
    if not os.path.exists(dst_dir):
        os.mkdir(dst_dir)
    new_smac = five_tuple['smac']
    new_dmac = five_tuple['dmac']
    new_sipv4 = five_tuple['sipv4']
    new_dipv4 = five_tuple['dipv4']
    new_sipv6 = five_tuple['sipv6']
    new_dipv6 = five_tuple['dipv6']

    for file in file_list:
        dirname, pcap_name = os.path.split(file)
        new_pcap = os.path.join(dst_dir, pcap_name)
        new_pkts = []
        pkts = rdpcap(file)
        old_smac = pkts[0]['Ether'].src
        old_dmac = pkts[0]['Ether'].dst
        for p in pkts:
            tmp = p.copy()

            try:
                del tmp["IP"].chksum
            except:
                pass
            try:
                del tmp["IPv6"].chksum
            except:
                pass
            try:
                del tmp['TCP'].chksum
            except:
                pass
            try:
                del tmp['UDP'].chksum
            except:
                pass
            if tmp['Ether'].src == old_smac:
                tmp['Ether'].src = new_smac
                tmp['Ether'].dst = new_dmac
                if not args['change_version']:
                    if tmp.haslayer('IP'):
                        tmp['IP'].src = new_sipv4
                        tmp['IP'].dst = new_dipv4
                    elif tmp.haslayer('IPv6'):
                        tmp['IPv6'].src = new_sipv6
                        tmp['IPv6'].dst = new_dipv6
                else:
                    if tmp.haslayer('IP'):
                        tmp = Ether(src=new_smac, dst=new_dmac) / IPv6(src=new_sipv6, dst=new_dipv6) / tmp['IP'].payload
                    elif tmp.haslayer('IPv6'):
                        tmp = Ether(src=new_smac, dst=new_dmac) / IP(src=new_sipv4, dst=new_dipv4) / tmp['IPv6'].payload
            if tmp['Ether'].dst == old_smac:
                tmp['Ether'].src = new_dmac
                tmp['Ether'].dst = new_smac
                if not args['change_version']:
                    if tmp.haslayer('IP'):
                        tmp['IP'].src = new_dipv4
                        tmp['IP'].dst = new_sipv4
                    elif tmp.haslayer('IPv6'):
                        tmp['IPv6'].src = new_dipv6
                        tmp['IPv6'].dst = new_sipv6
                else:
                    if tmp.haslayer('IP'):
                        tmp = Ether(src=new_dmac, dst=new_smac) / IPv6(src=new_dipv6, dst=new_sipv6) / tmp['IP'].payload
                    elif tmp.haslayer('IPv6'):
                        tmp = Ether(src=new_dmac, dst=new_smac) / IP(src=new_dipv4, dst=new_sipv4) / tmp['IPv6'].payload
            new_pkts.append(tmp)
        wrpcap(new_pcap, new_pkts)


def parse_args():
    desc = """
pcap文件mac、ip修改工具
- 只支持包含单条流的pcap文件
- 根据首包的mac地址, 判断后续包的方向, 修改对应的mac和ip地址
- 只支持固网包
- 支持ipv4/ipv6/tcp/udp
- 生成的新报文, 会重新计算各个chksum
- 生成的新报文, 按原名保存到 dst_dir 目录下
- 支持ipv4和ipv6互换, 此时只支持结构为 Ether/IP 或 Ether/IPv6 的报文, 且Ether会舍弃原来的, 重新构造
    """
    p = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument('-f', '--file', required=True, help='原始pcap文件或存放目录')
    p.add_argument('--dst_dir', help=f'修改后的pcap文件存放目录, default: {dst_dir}')
    p.add_argument('--smac', help=f'smac, default: {default_smac}')
    p.add_argument('--dmac', help=f'dmac, default: {default_dmac}')
    p.add_argument('--sipv4', help=f'sipv4, default: {default_sipv4}')
    p.add_argument('--dipv4', help=f'dipv4, default: {default_dipv4}')
    p.add_argument('--sipv6', help=f'sipv6, default: {default_sipv6}')
    p.add_argument('--dipv6', help=f'dipv6, default: {default_dipv6}')
    p.add_argument('-v', '--change_version', action='store_true', help='配置时, 表示修改ip版本, 即从ipv4修改为ipv6或从ipv6修改为ipv4, 同时Ether层会重新构造, 且不支持带vlan的情况')

    args = vars(p.parse_args())
    return args


def main():

    file_list = get_file_list()
    print(file_list)
    five_tuple = {
        'smac': args['smac'] if args['smac'] else default_smac,
        'dmac': args['dmac'] if args['dmac'] else default_dmac,
        'sipv4': args['sipv4'] if args['sipv4'] else default_sipv4,
        'dipv4': args['dipv4'] if args['dipv4'] else default_dipv4,
        'sipv6': args['sipv6'] if args['sipv6'] else default_sipv6,
        'dipv6': args['dipv6'] if args['dipv6'] else default_dipv6,

    }
    change_pcap(file_list, five_tuple, dst_dir)


if __name__ == "__main__":
    dst_dir = './dst_pcap'
    default_smac = "10:00:00:00:00:00"
    default_dmac = "20:00:00:00:00:00"
    default_sipv4 = "1.1.1.1"
    default_dipv4 = "2.2.2.2"
    default_sipv6 = "2022::1:1"
    default_dipv6 = "2022::1:2"

    args = parse_args()
    print(args)
    main()
