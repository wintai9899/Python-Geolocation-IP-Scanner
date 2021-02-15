# coding: utf-8
import struct
import socket
import io
import sys


class QQwryFinder:
    def __init__(self, db_file='qqwry.dat'):
        self.f_db = open(db_file, "rb")
        bs = self.f_db.read(8)
        self.first_index, self.last_index = struct.unpack('II', bs)
        self.index_count = int((self.last_index - self.first_index) / 7 + 1)
        self.cur_start_ip = None
        self.cur_end_ip_offset = None
        self.cur_end_ip = None

    def _get_area_addr(self, offset=0):
        if offset:
            self.f_db.seek(offset)
        bs = self.f_db.read(1)
        (byte,) = struct.unpack('B', bs)
        if byte == 0x01 or byte == 0x02:
            p = self.getLong3()
            if p:
                return self.get_offset_string(p)
            else:
                return ""
        else:
            self.f_db.seek(-1, 1)
            return self.get_offset_string(offset)

    def _get_addr(self, offset):
        '''
        获取offset处记录区地址信息(包含国家和地区)
        '''

        self.f_db.seek(offset + 4)
        bs = self.f_db.read(1)
        (byte,) = struct.unpack('B', bs)
        if byte == 0x01:  # 重定向模式1
            country_offset = self.getLong3()
            self.f_db.seek(country_offset)
            bs = self.f_db.read(1)
            (b,) = struct.unpack('B', bs)
            if b == 0x02:
                country_addr = self.get_offset_string(self.getLong3())
                self.f_db.seek(country_offset + 4)
            else:
                country_addr = self.get_offset_string(country_offset)
            area_addr = self._get_area_addr()
        elif byte == 0x02:  # 重定向模式2
            country_addr = self.get_offset_string(self.getLong3())
            area_addr = self._get_area_addr(offset + 8)
        else:  # 字符串模式
            country_addr = self.get_offset_string(offset + 4)
            area_addr = self._get_area_addr()
        result = {}
        result['country'] = country_addr
        result['area'] = area_addr
        return result

    def dump(self, first, last):
        '''
        打印数据库中索引为first到索引为last(不包含last)的记录
        :param first:
        :param last:
        :return:
        '''
        if last > self.index_count:
            last = self.index_count
        for index in range(first, last):
            offset = self.first_index + index * 7
            self.f_db.seek(offset)
            buf = self.f_db.read(7)
            (ip, of1, of2) = struct.unpack("IHB", buf)
            address = self._get_addr(of1 + (of2 << 16))
            print("%d %s %s" % (index, self.ip2str(ip), address))

    def _set_ip_range(self, index):
        offset = self.first_index + index * 7
        self.f_db.seek(offset)
        buf = self.f_db.read(7)
        (self.cur_start_ip, of1, of2) = struct.unpack("IHB", buf)
        self.cur_end_ip_offset = of1 + (of2 << 16)
        self.f_db.seek(self.cur_end_ip_offset)
        buf = self.f_db.read(4)
        (self.cur_end_ip,) = struct.unpack("I", buf)

    def get_addr_by_ip(self, ip):
        '''
        通过ip查找其地址
        :param ip: (int or str)
        :return: str
        '''
        if type(ip) == str:
            ip = self.str2ip(ip)
        L = 0
        R = self.index_count - 1
        while L < R - 1:
            M = int((L + R) / 2)
            self._set_ip_range(M)
            if ip == self.cur_start_ip:
                L = M
                break
            if ip > self.cur_start_ip:
                L = M
            else:
                R = M
        self._set_ip_range(L)
        # version information, 255.255.255.X, urgy but useful
        if ip & 0xffffff00 == 0xffffff00:
            self._set_ip_range(R)
        if self.cur_start_ip <= ip <= self.cur_end_ip:
            address = self._get_addr(self.cur_end_ip_offset)
        else:
            address = "未找到该IP的地址"
        return address

    def get_ip_range(self, ip):
        '''
        返回ip所在记录的IP段
        :param ip: ip(str or int)
        :return: str
        '''
        if type(ip) == str:
            ip = self.str2ip(ip)
        self.get_addr_by_ip(ip)
        range = self.ip2str(self.cur_start_ip) + ' - ' \
                + self.ip2str(self.cur_end_ip)
        return range

    def get_offset_string(self, offset=0):
        '''
        获取文件偏移处的字符串(以'\0'结尾)
        :param offset: 偏移
        :return: str
        '''
        if offset:
            self.f_db.seek(offset)
        bs = b''
        ch = self.f_db.read(1)
        (byte,) = struct.unpack('B', ch)
        while byte != 0:
            bs += ch
            ch = self.f_db.read(1)
            (byte,) = struct.unpack('B', ch)
        return bs.decode('gbk')

    def ip2str(self, ip):
        '''
        整数IP转化为IP字符串
        :param ip:
        :return:
        '''
        return str(ip >> 24) + '.' + str((ip >> 16) & 0xff) + '.' + str((ip >> 8) & 0xff) + '.' + str(ip & 0xff)

    def str2ip(self, s):
        '''
        IP字符串转换为整数IP
        :param s:
        :return:
        '''
        (ip,) = struct.unpack('I', socket.inet_aton(s))
        return ((ip >> 24) & 0xff) | ((ip & 0xff) << 24) | ((ip >> 8) & 0xff00) | ((ip & 0xff00) << 8)

    def getLong3(self, offset=0):
        '''
        3字节的数值
        '''
        if offset:
            self.f_db.seek(offset)
        bs = self.f_db.read(3)
        (a, b) = struct.unpack('HB', bs)
        return (b << 16) + a


class Ip2Region(object):
    __INDEX_BLOCK_LENGTH = 12
    __TOTAL_HEADER_LENGTH = 8192

    __f = None
    __headerSip = []
    __headerPtr = []
    __headerLen = 0
    __indexSPtr = 0
    __indexLPtr = 0
    __indexCount = 0
    __dbBinStr = ''

    def __init__(self, dbfile):
        self.initDatabase(dbfile)

    def memorySearch(self, ip):
        """
        " memory search method
        " param: ip
        """
        if not ip.isdigit(): ip = self.ip2long(ip)

        if self.__dbBinStr == '':
            self.__dbBinStr = self.__f.read()  # read all the contents in file
            self.__indexSPtr = self.getLong(self.__dbBinStr, 0)
            self.__indexLPtr = self.getLong(self.__dbBinStr, 4)
            self.__indexCount = int((self.__indexLPtr - self.__indexSPtr) / self.__INDEX_BLOCK_LENGTH) + 1

        l, h, dataPtr = (0, self.__indexCount, 0)
        while l <= h:
            m = int((l + h) >> 1)
            p = self.__indexSPtr + m * self.__INDEX_BLOCK_LENGTH
            sip = self.getLong(self.__dbBinStr, p)

            if ip < sip:
                h = m - 1
            else:
                eip = self.getLong(self.__dbBinStr, p + 4)
                if ip > eip:
                    l = m + 1
                else:
                    dataPtr = self.getLong(self.__dbBinStr, p + 8)
                    break

        if dataPtr == 0: raise Exception("Data pointer not found")

        return self.returnData(dataPtr)

    def binarySearch(self, ip):
        """
        " binary search method
        " param: ip
        """
        if not ip.isdigit(): ip = self.ip2long(ip)

        if self.__indexCount == 0:
            self.__f.seek(0)
            superBlock = self.__f.read(8)
            self.__indexSPtr = self.getLong(superBlock, 0)
            self.__indexLPtr = self.getLong(superBlock, 4)
            self.__indexCount = int((self.__indexLPtr - self.__indexSPtr) / self.__INDEX_BLOCK_LENGTH) + 1

        l, h, dataPtr = (0, self.__indexCount, 0)
        while l <= h:
            m = int((l + h) >> 1)
            p = m * self.__INDEX_BLOCK_LENGTH

            self.__f.seek(self.__indexSPtr + p)
            buffer = self.__f.read(self.__INDEX_BLOCK_LENGTH)
            sip = self.getLong(buffer, 0)
            if ip < sip:
                h = m - 1
            else:
                eip = self.getLong(buffer, 4)
                if ip > eip:
                    l = m + 1
                else:
                    dataPtr = self.getLong(buffer, 8)
                    break

        if dataPtr == 0: raise Exception("Data pointer not found")

        return self.returnData(dataPtr)

    def btreeSearch(self, ip):
        """
        " b-tree search method
        " param: ip
        """
        if not ip.isdigit(): ip = self.ip2long(ip)

        if len(self.__headerSip) < 1:
            headerLen = 0
            # pass the super block
            self.__f.seek(8)
            # read the header block
            b = self.__f.read(self.__TOTAL_HEADER_LENGTH)
            # parse the header block
            for i in range(0, len(b), 8):
                sip = self.getLong(b, i)
                ptr = self.getLong(b, i + 4)
                if ptr == 0:
                    break
                self.__headerSip.append(sip)
                self.__headerPtr.append(ptr)
                headerLen += 1
            self.__headerLen = headerLen

        l, h, sptr, eptr = (0, self.__headerLen, 0, 0)
        while l <= h:
            m = int((l + h) >> 1)

            if ip == self.__headerSip[m]:
                if m > 0:
                    sptr = self.__headerPtr[m - 1]
                    eptr = self.__headerPtr[m]
                else:
                    sptr = self.__headerPtr[m]
                    eptr = self.__headerPtr[m + 1]
                break

            if ip < self.__headerSip[m]:
                if m == 0:
                    sptr = self.__headerPtr[m]
                    eptr = self.__headerPtr[m + 1]
                    break
                elif ip > self.__headerSip[m - 1]:
                    sptr = self.__headerPtr[m - 1]
                    eptr = self.__headerPtr[m]
                    break
                h = m - 1
            else:
                if m == self.__headerLen - 1:
                    sptr = self.__headerPtr[m - 1]
                    eptr = self.__headerPtr[m]
                    break
                elif ip <= self.__headerSip[m + 1]:
                    sptr = self.__headerPtr[m]
                    eptr = self.__headerPtr[m + 1]
                    break
                l = m + 1

        if sptr == 0: raise Exception("Index pointer not found")

        indexLen = eptr - sptr
        self.__f.seek(sptr)
        index = self.__f.read(indexLen + self.__INDEX_BLOCK_LENGTH)

        l, h, dataPrt = (0, int(indexLen / self.__INDEX_BLOCK_LENGTH), 0)
        while l <= h:
            m = int((l + h) >> 1)
            offset = int(m * self.__INDEX_BLOCK_LENGTH)
            sip = self.getLong(index, offset)

            if ip < sip:
                h = m - 1
            else:
                eip = self.getLong(index, offset + 4)
                if ip > eip:
                    l = m + 1;
                else:
                    dataPrt = self.getLong(index, offset + 8)
                    break

        if dataPrt == 0: raise Exception("Data pointer not found")

        return self.returnData(dataPrt)

    def initDatabase(self, dbfile):
        """
        " initialize the database for search
        " param: dbFile
        """
        try:
            self.__f = io.open(dbfile, "rb")
        except IOError as e:
            print("[Error]: %s" % e)
            sys.exit()

    def returnData(self, dataPtr):
        """
        " get ip data from db file by data start ptr
        " param: dsptr
        """
        dataLen = (dataPtr >> 24) & 0xFF
        dataPtr = dataPtr & 0x00FFFFFF

        self.__f.seek(dataPtr)
        data = self.__f.read(dataLen)

        return {
            "city_id": self.getLong(data, 0),
            "region": data[4:]
        }

    def ip2long(self, ip):
        _ip = socket.inet_aton(ip)
        return struct.unpack("!L", _ip)[0]

    def isip(self, ip):
        p = ip.split(".")

        if len(p) != 4: return False
        for pp in p:
            if not pp.isdigit(): return False
            if len(pp) > 3: return False
            if int(pp) > 255: return False

        return True

    def getLong(self, b, offset):
        if len(b[offset:offset + 4]) == 4:
            return struct.unpack('I', b[offset:offset + 4])[0]
        return 0

    def close(self):
        if self.__f != None:
            self.__f.close()

        self.__dbBinStr = None
        self.__headerPtr = None
        self.__headerSip = None


class GetIPInfo(object):
    def __init__(self, qqwry_db="qqwry.dat", ip2region_db="ip2region.db"):
        self.searcher_ip2region = Ip2Region(ip2region_db)  # 实例化
        self.searcher_qqwry = QQwryFinder(db_file=qqwry_db)

    def query(self, ip):
        result = {"country": "", "province": "", "city": "", "isp": "", "area": ""}

        qqwry = self.query_qqwry(ip)
        result["area"] = qqwry["area"]

        ip2region = self.query_ip2region(ip)
        result["country"] = ip2region["country"]
        result["province"] = ip2region["province"]
        result["city"] = ip2region["city"]
        result["isp"] = ip2region["isp"]

        if result["isp"] == result["area"] and all([result["isp"], result["area"]]):
            result["area"] = ""
        return result

    def query_qqwry(self, ip):
        try:
            result = self.searcher_qqwry.get_addr_by_ip(ip)
        except Exception as e:
            print("QQwry Query Error: {} {}".format(ip, e))
            result = {"country": "", "area": ""}
        finally:
            return result

    def query_ip2region(self, ip):
        
        try:
            data = self.searcher_ip2region.memorySearch(ip)  # B树
            # data = searcher.binarySearch(line) #二进制
            # data = searcher.memorySearch(line) #内存
            items = data["region"].decode("utf-8").split("|")
            country, _, province, city, isp = map(lambda x: "" if x == "0" else x, items)

        except Exception as e:
            print("IP2Region Query Error: {} {}".format(ip, e))
            country = province = city = isp = ""
        result = {"country": country, "province": province, "city": city, "isp": isp}
        return result


if __name__ == "__main__":
    geo = GetIPInfo()
    #输入查询ip地址
    ip_info = geo.query("202.69.26.144")

    import json

    print(json.dumps(ip_info, indent=4, ensure_ascii=False))
