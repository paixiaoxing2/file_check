from watchdog.observers import Observer
from watchdog.events import *
import json
import os, requests
import time
import yara
import sys
import prettytable as pt

# 检查是否root运行
def checkroot():
    if os.popen("whoami").read() != 'root\n':
        print('[\033[1;36mwaring\033[0m]检测到当前为非root权限，部分功能可能受限哦~')

#文件上传检测，发到检测平台检测
def uploadfile_baiducheck(filename):
    try:
        upload_cmd = "curl https://scanner.baidu.com/enqueue -F archive=@%s" % filename
        res = os.popen(upload_cmd).read()  # os.system是没有返回结果的所以使用popen
        res = json.loads(res)
        resurl = res['url'];
        # print(resurl)
        result = requests.get(resurl).json()
        # print(result)
        time.sleep(1)
        if result[0]['data'] == None:  # 访问失败的时候延迟
            time.sleep(2)
            result = requests.get(resurl).json()
            descr = result[0]['data'][0]['descr']
            f = open('./checkfile.txt', 'a')
            f.write('\n')
            if descr != None:
                print("【++++++++++++++++++++++++】")
                print(filename)
                print("该文件经百度检测文件为webshell")
                print("经百度检测webshell名称为：" + '\n' + descr)
                f.write("【++++++++++++++++++++++++】")
                f.write('\n')
                f.write('该文件经百度检测文件为webshell')
                f.write('\n')
                f.write(filename)
                f.write('\n')
                f.write("经百度检测webshell名称为：" + '\n' + descr)
                f.write('\n')
                back = open(filename, 'r')
                # print(back.readlines())
                backdoor = back.readlines()
                print(backdoor[0])
                # print(type(str(back.readlines())))
                f.write(backdoor[0])
                f.write('\n\n\n')
                f.close()
                os.system("rm -rf " + filename)
                if os.path.exists(filename):
                    print("文件删除失败，尝试再次删除")
                    os.unlink(filename)
                else:
                    print("文件夹已删除")
            else:
                print("【-----------------------】")
                print(filename)
                print('该文件经百度检测不是webshell')
                print('\n')
                f.write("【-----------------------】")
                f.write('\n')
                f.write('该文件经百度检测不是webshell')
                f.write('\n')
                f.write(filename)
                f.write('\n')
                f.write('\n\n\n')
                f.close()

        else:  # 访问成功直接提取结果
            descr = result[0]['data'][0]['descr']
            f = open('./checkfile.txt', 'a')
            f.write('\n')
            if descr != None:
                print("【++++++++++++++++++++++++】")
                print(filename)
                print("该文件经百度检测文件为webshell")
                print("经百度检测webshell名称为：" + '\n' + descr)
                f.write("【++++++++++++++++++++++++】")
                f.write('\n')
                f.write('该文件经百度检测文件为webshell')
                f.write('\n')
                f.write(filename)
                f.write('\n')
                f.write("经百度检测webshell名称为：" + '\n' + descr)
                f.write('\n')
                back = open(filename, 'r')
                # print(back.readlines())
                backdoor = back.readlines()
                print(backdoor[0])
                # print(type(str(back.readlines())))
                f.write(backdoor[0])
                f.write('\n\n\n')
                f.close()
                os.system("rm -rf "+ filename)

            else:
                print("【-----------------------】")
                print(filename)
                print('该文件经百度检测不是webshell')
                print('\n')
                f.write("【-----------------------】")
                f.write('\n')
                f.write('该文件经百度检测不是webshell')
                f.write('\n')
                f.write(filename)
                f.write('\n')
            f.write('\n\n\n')
            f.close()
    except Exception as e:
        print("百度webshell检测不支持的后缀")
        print(filename)
        pass

#用yara语法检测
def webshell_scan(path):
    webshell = pt.PrettyTable()
    webshell.field_names = ['Path', 'LastChange']
    webshell.align["Path"] = "l"  # 路径字段靠右显示
    rule = yara.compile(filepath=r'rules/webshell.yar')
    print('\033[1;34m读取待检测文件中...\033[0m')
    all = os.popen("find " + path).read().split('\n')
    file_list = []  # 过滤后的文件列表
    print('\033[1;32m读取完毕，开始过滤...\033[0m')
    for file in all:  # 过滤掉部分文件
        try:
            fsize = os.path.getsize(file) / float(1024 * 1024)
        except:
            fsize = 6
        if fsize <= 5:  # 只检测小于5M的文件
            file_list.append(file)
    print('\033[1;32m过滤完毕，开始扫描...\033[0m')
    for i in range(len(file_list)):
        sys.stdout.write('\033[K' + '\r')
        print('\r','[{0}/{1}]检测中,耐心等待哦~'.format(str(i), str(len(file_list))),end=' ')
        try:
            with open(file_list[i], 'rb') as f:
                matches = rule.match(data=f.read())
        except:
            matches = []
        try:
            if matches != []:
                time_chuo = time.localtime(os.path.getmtime(file_list[i]))  # 最后修改时间戳
                lasttime = time.strftime("%Y--%m--%d %H:%M:%S", time_chuo)  # 最后修改时间
                warning = ('\033[1;31m\n告警：检测到标签{0}，文件位置{1}\033[0m'.format(matches, file_list[i]))
                webshell.add_row([file_list[i], lasttime])
                print(warning)
        except:
            pass
    print('\033[1;32m\n所有文件扫描完成，结果如下：\n\033[0m')
    print(webshell)

class FileEventHandler(FileSystemEventHandler):
    def __init__(self):
        FileSystemEventHandler.__init__(self)

    def on_moved(self, event):
        if event.is_directory:
            print("移动文件夹 from {0} to {1}".format(event.src_path, event.dest_path))
        else:
            print("移动文件 from {0} to {1}".format(event.src_path, event.dest_path))

    def on_created(self, event):
        if event.is_directory:
            print("文件夹创建:{0}".format(event.src_path))
        else:
            print("文件创建:{0}".format(event.src_path))
            uploadfile_baiducheck(event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            print("文件夹删除:{0}".format(event.src_path))
        else:
            print("文件删除:{0}".format(event.src_path))

    def on_modified(self, event):
        if event.is_directory:
            # print("文件夹修改:{0}".format(event.src_path))
            pass
        else:
            # print("文件修改:{0}".format(event.src_path))
            pass





if __name__ == "__main__":
    checkroot()
    observer = Observer()
    event_handler = FileEventHandler()
    observer.schedule(event_handler, r"/Users/miaoguoyang/Workspace/blueteam/watchdog/demo", True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
