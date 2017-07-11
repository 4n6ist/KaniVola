using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using System.Reflection;

namespace KaniVolatility
{

    public partial class Form1 : Form
    {
        static public List<int> KnownId = new List<int>();   // プロセス停止チェック用
        static public string PrevInputFileName, PrevProfileName, PrevOutputDumpFolderName; //  対象ファイル、プロファイル、出力フォルダ(ダンプ用)の控え
        //  起動時
        public Form1()
        {
            InitializeComponent();
            cmbProfile.Enabled = false;
            cmbCategory.Enabled = false;
            cmbCommand.Enabled = false;
            btnCmdHelp.Enabled = false;
            btnRun.Enabled = false;
            btnOutput.Enabled = false;
            chkPlugins.Enabled = false;
            if (!File.Exists("volatility.exe"))
            {
                MessageBox.Show("volatilityプログラムが存在しません。\r\n\r\n"
                  + "公式サイト(http://www.volatilityfoundation.org/)からWindowsプログラム(Volatility 2.6 Windows Standalone Executable (x64))を入手してください。\r\n\r\n"
                  + "入手したファイルのファイル名をvolatility.exeに変更してからKaniVola.exeと同じフォルダに配置し、再度実行してください。",
                  "実行エラー", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(0);
            }

            cmbProfile.Items.Clear();
            string line = "";
            if (!File.Exists(@"conf\profiles.txt"))
            {
                MessageBox.Show("conf\\profiles.txtが存在しません。\r\n"
                    + "読み込むプロファイル名を列挙したテキストを作成して配置してください。\r\n",
                    "実行エラー", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(0);
            }

            if (!File.Exists(@"conf\dumpcmd.txt"))
            {
                MessageBox.Show("conf\\dumpcmd.txtが存在しません。\r\n"
                    + "-Dオプションを使うコマンドを列挙したテキストを配置してください。配置しない場合はオプションを手動で設定してください。\r\n",
                    "警告", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }

            StreamReader profFile = new StreamReader(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\conf\profiles.txt", System.Text.Encoding.Default);

            while (profFile.Peek() >= 0)
            {
                line = profFile.ReadLine();
                if (line.StartsWith("//"))
                    continue;
                cmbProfile.Items.Add(line);
            }
            profFile.Close();
            cmbProfile.Items.Add("Linux/Mac");

            cmbCategory.Items.Add("イメージスキャン/変換"); // 初期選択可能カテゴリ
            cmbCategory.SelectedIndex = 0;
        }

        // 対象ファイルの選択ボタンクリック時
        private void buttonInputFile_Click(object sender, EventArgs e)
        {
            if (DialogResult.OK == openFileDialog.ShowDialog())
            {
                txtInput.Text = openFileDialog.FileName;
                if (Path.GetDirectoryName(txtInput.Text).EndsWith(@"\") == true)
                    txtOutput.Text = Path.GetDirectoryName(txtInput.Text) + Path.GetFileNameWithoutExtension(txtInput.Text) + "_Output";
                else
                    txtOutput.Text = Path.GetDirectoryName(txtInput.Text) + @"\" + Path.GetFileNameWithoutExtension(txtInput.Text) + "_Output";

                // pluginsチェックボックスがONならコントロール処理をスキップ
                if (chkPlugins.Checked == false) {
                    cmbProfile.Enabled = true;
                    cmbCommand.SelectedIndex = 0; // imageinfoを選択状態にする
                    cmbCommand.Enabled = true;
                    btnOutput.Enabled = true;
                    btnRun.Enabled = true;
                }

                buildCommandline(sender, e);
            }
        }

        // 対象ファイルのテキストボックスへのドラッグ&ドロップ時
        private void textBoxInput_DragDrop(object sender, DragEventArgs e)
        {
            string[] data = (string[])e.Data.GetData("FileDrop", false);
            if (File.Exists(data[0]))
            {
                txtInput.Text = data[0];
                if (Path.GetDirectoryName(txtInput.Text).EndsWith(@"\") == true)
                    txtOutput.Text = Path.GetDirectoryName(txtInput.Text) + Path.GetFileNameWithoutExtension(txtInput.Text) + "_Output";
                else
                    txtOutput.Text = Path.GetDirectoryName(txtInput.Text) + @"\" + Path.GetFileNameWithoutExtension(txtInput.Text) + "_Output";

                // pluginsチェックボックスがONならコントロール処理をスキップ
                if (chkPlugins.Checked == false) {
                    cmbProfile.Enabled = true;
                    cmbCommand.SelectedIndex = 0; // imageinfoを選択状態にする
                    cmbCommand.Enabled = true;
                    btnOutput.Enabled = true;
                    btnRun.Enabled = true;
                }

                buildCommandline(sender, e);
            }
        }

        // 出力フォルダの選択ボタンクリック時
        private void buttonOutput_Click(object sender, EventArgs e)
        {
            if (DialogResult.OK == folderBrowserDialogOutput.ShowDialog())
                txtOutput.Text = folderBrowserDialogOutput.SelectedPath;
            buildCommandline(sender, e);
        }

        // 出力フォルダのテキストボックスへのドラッグ&ドロップ時
        private void textBoxOutput_DragDrop(object sender, DragEventArgs e)
        {
            string[] data = (string[])e.Data.GetData("FileDrop", false);
            if (Directory.Exists(data[0]))
            {
                String[] files = Directory.GetFiles(data[0], "*");
                txtOutput.Text = data[0];

                buildCommandline(sender, e);
            }
        }

        // 対象ファイル&出力フォルダのテキストボックスへのドラッグ&ドロップ用
        private void textBox_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
                e.Effect = DragDropEffects.All;
            else
                e.Effect = DragDropEffects.None;
        }

        // プロファイル項目変更時
        private void cmbProfile_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (cmbProfile.SelectedItem.ToString() == "Linux/Mac")
            {
                DialogResult result = MessageBox.Show(this, "KaniVola.exeがある場所にprofilesフォルダを作成してください。\r\n\r\n"
                  + "そのフォルダ配下に追加対象プロファイル(zip形式)を配置してからOKボタンを押してください。\r\n\r\n"
                  + "認識したプロファイルを一覧に追加します。",
                  "プロファイルの追加", MessageBoxButtons.OKCancel, MessageBoxIcon.Asterisk);
                if (result == DialogResult.OK)
                {
                    chkPlugins.Checked = false;
                    chkPlugins.Enabled = false;
                    txtCommandLine.Text = "--plugins=profiles --info";
                    txtStdOutput.Text = "> volatility.exe " + txtCommandLine.Text + "\r\n";
                    RunVolatilityStdout();
                    cmbCategory.Items.Clear();
                    cmbCommand.Items.Clear();
                    cmbCommand.Text = "";
                }
                return;
            }
            else if (cmbProfile.SelectedItem.ToString().Contains("Linux") == true || cmbProfile.SelectedItem.ToString().Contains("Mac") == true)
            {
                // プロファイルが新規または別OSからLinuxまたはMacに変更された場合はカテゴリリストを再作成
                if (PrevProfileName != "Linux" || PrevProfileName != "Mac")
                {
                    chkPlugins.Checked = false;
                    chkPlugins.Enabled = false;
                    cmbCategory.Items.Clear();
                    cmbCategory.Items.AddRange(new object[] {
                        "プロセス",
                        "プロセスメモリ",
                        "カーネルメモリ/オブジェクト",
                        "ネットワーク",
                        "マルウェア",
                        "システム情報",
                        "その他",
                        "イメージスキャン/変換",
                        "バッチ処理"
                    });
                    txtCommandLine.Text = "--plugins=profiles --profile=" + cmbProfile.SelectedItem + " -f \"" + txtInput.Text + "\" " + cmbCommand.SelectedItem;
                    cmbCommand.Items.Clear();
                    cmbCommand.Text = "";
                    cmbCategory.Enabled = true;
                }
                else
                {
                    buildCommandline(sender, e);
                }
            }
            else // Windows用
            {
                chkPlugins.Enabled = true;

                // プロファイルが新規に選択された場合は現在の状態を維持しつつカテゴリリストを作成
                if (PrevProfileName == null)
                {
                    cmbCategory.Items.Clear();
                    cmbCategory.Items.AddRange(new object[] {
                        "プロセス/DLL",
                        "プロセスメモリ",
                        "カーネルメモリ/オブジェクト",
                        "レジストリ",
                        "ネットワーク",
                        "ファイルシステム",
                        "マルウェア",
                        "Windows GUI",
                        "その他",
                        "イメージスキャン/変換",
                        "コミュニティ",
                        "バッチ処理"
                    });
                    cmbCategory.SelectedIndex = 9; // イメージスキャン/変換
                }
                // プロファイルが別OSからWinに変更された場合はカテゴリリストを再作成
                else if (PrevProfileName.Contains("Mac") == true || PrevProfileName.Contains("Linux") == true)
                {
                    buildCommandline(sender, e);
                    cmbCommand.Items.Clear();
                }
                else
                {
                    buildCommandline(sender, e);
                }

                if (chkPlugins.Checked == false)
                    cmbCategory.Enabled = true;

                chkPlugins.Enabled = true;
                PrevProfileName = cmbProfile.Text;

            }

            buildCommandline(sender, e);
        }

        // カテゴリ項目変更時
        private void comboBox2_SelectedIndexChanged(object sender, EventArgs e)
        {
            cmbCommand.Items.Clear();
            // 共通
            if (cmbCategory.SelectedIndex == 0 && (string)cmbCategory.SelectedItem == "イメージスキャン/変換")
            {
                cmbCommand.Items.AddRange(new object[] {
                    "imageinfo",
                    "kdbgscan",
                    "kpcrscan",
                    "crashinfo",
                    "hibinfo",
                    "imagecopy",
                    "raw2dmp",
                    "vboxinfo",
                    "vmwareinfo",
                    "hpakinfo",
                    "hpakextract",
                    "limeinfo",
                    "mac_get_profile",
                    "machoinfo",
                    "qemuinfo"
                });
                return;
            }
            // Linuxプロファイルの場合
            else if (cmbProfile.SelectedItem.ToString().Contains("Linux") == true)
            {
                if ((string)cmbCategory.SelectedItem == "プロセス")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "linux_pslist",
                        "linux_psscan",
                        "linux_psaux",
                        "linux_pstree",
                        "linux_pslist_cache",
                        "linux_pidhashtable",
                        "linux_psxview",
                        "linux_lsof",
                        "linux_psenv"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "プロセスメモリ")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "linux_memmap",
                        "linux_proc_maps",
                        "linux_dump_map",
                        "linux_bash",
                        "linux_bash_env",
                        "linux_bash_hash",
                        "linux_dynamic_env",
                        "linux_elfs",
                        "linux_library_list",
                        "linux_librarydump",
                        "linux_proc_maps_rb",
                        "linux_procdump"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "カーネルメモリ/オブジェクト")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "linux_lsmod",
                        "linux_moddump",
                        "linux_tmpfs",
                        "linux_enumerate_files",
                        "linux_info_regs",
                        "linux_kernel_opened_files",
                        "linux_recover_filesystem"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "マルウェア")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "linux_check_afinfo",
                        "linux_check_tty",
                        "linux_keyboard_notifiers",
                        "linux_check_creds",
                        "linux_check_fop",
                        "linux_check_idt",
                        "linux_check_syscall",
                        "linux_check_modules",
                        "linux_apihooks",
                        "linux_check_evt_arm",
                        "linux_check_inline_kernel",
                        "linux_check_syscall_arm",
                        "linux_hidden_modules",
                        "linux_ldrmodules",
                        "linux_malfind",
                        "linux_plthook",
                        "linux_process_hollow"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "ネットワーク")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "linux_arp",
                        "linux_ifconfig",
                        "linux_route_cache",
                        "linux_netstat",
                        "linux_pkt_queues",
                        "linux_sk_buff_cache",
                        "linux_list_raw",
                        "linux_netscan"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "システム情報")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "linux_cpuinfo",
                        "linux_dmesg",
                        "linux_iomem",
                        "linux_slabinfo",
                        "linux_mount",
                        "linux_mount_cache",
                        "linux_dentry_cache",
                        "linux_find_file",
                        "linux_vma_cache",
                        "linux_banner"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "その他")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "linux_yarascan",
                        "linux_strings",
                        "linux_truecrypt_passphrase",
                        "linux_threads"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "イメージスキャン/変換")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "imagecopy",
                        "vboxinfo",
                        "vmwareinfo",
                        "hpakinfo",
                        "hpakextract",
                        "limeinfo",
                        "qemuinfo"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "コミュニティ")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "kstackps",
                        "linux_ffcookies",
                        "linux_ffhis",
                        "linux_python_str_dict_entry",
                        "linux_python_strings",
                        "linux_ssh_keys",
                        "linuxgetprofile"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "バッチ処理")
                {
                    DialogResult result = MessageBox.Show(this, "conf\\batch_linux.txtに記載されたコマンドを一括実行します。\r\n"
                        + "必要であればこの時点で編集してください。OKを押すと処理を開始します。",
                        "バッチ処理", MessageBoxButtons.OKCancel, MessageBoxIcon.Asterisk);
                    if (result == DialogResult.OK)
                        RunVolatilityBatch();
                    else
                        cmbCategory.SelectedIndex = 0;
                    return;
                }
            }
            // Macプロファイルの場合
            else if (cmbProfile.SelectedItem.ToString().Contains("Mac") == true)
            {
                if ((string)cmbCategory.SelectedItem == "プロセス")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "mac_pslist",
                        "mac_tasks",
                        "mac_pstree",
                        "mac_lsof",
                        "mac_pgrp_hash_table",
                        "mac_pid_hash_table",
                        "mac_psaux",
                        "mac_dead_procs",
                        "mac_psxview"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "プロセスメモリ")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "mac_proc_maps",
                        "mac_dump_maps",
                        "mac_bash",
                        "mac_bash_env",
                        "mac_bash_hash",
                        "mac_memdump",
                        "mac_procdump",
                        "mac_compressed_swap"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "カーネルメモリ/オブジェクト")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "mac_list_sessions",
                        "mac_list_zones",
                        "mac_lsmod",
                        "mac_mount",
                        "mac_compressed_swap",
                        "mac_dead_vnodes",
                        "mac_dump_file",
                        "mac_dyld_maps",
                        "mac_list_files",
                        "mac_list_kauth_listeners",
                        "mac_list_kauth_scopes",
                        "mac_lsmod_iokit",
                        "mac_lsmod_kext_map",
                        "mac_moddump",
                        "mac_recover_filesystem",
                        "mac_devfs",
                        "mac_interesr_handlers",
                        "mac_kernel_classes",
                        "mac_kevents",
                        "mac_timers",
                        "mac_vfsevents"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "ネットワーク")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "mac_arp",
                        "mac_ifconfig",
                        "mac_netstat",
                        "mac_route",
                        "mac_dead_sockets",
                        "mac_list_raw",
                        "mac_network_conns",
                        "mac_socket_filters"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "マルウェア")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "mac_check_sysctl",
                        "mac_check_syscalls",
                        "mac_check_trap_table",
                        "mac_ip_filters",
                        "mac_notifiers",
                        "mac_trustedbsd",
                        "mac_apihooks",
                        "mac_apihooks_kernel",
                        "mac_check_mig_table",
                        "mac_check_syscall_shadow",
                        "mac_malfind",
                        "mac_orphan_threads",
                        "mac_check_fop"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "システム情報")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "mac_dmesg",
                        "mac_find_aslr_shift",
                        "mac_machine_info",
                        "mac_version",
                        "mac_print_boot_cmdline"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "その他")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "mac_yarascan",
                        "mac_adium",
                        "mac_calendar",
                        "mac_contacts",
                        "mac_keychaindump",
                        "mac_notesapp",
                        "mac_strings",
                        "mac_threads",
                        "mac_threads_simple"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "イメージスキャン/変換")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "imagecopy",
                        "vboxinfo",
                        "vmwareinfo",
                        "hpakinfo",
                        "hpakextract",
                        "qemuinfo",
                        "machoinfo",
                        "mac_get_profile"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "コミュニティ")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "filevault2"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "バッチ処理")
                {
                    DialogResult result = MessageBox.Show(this, "conf\\batch_macosx.txtに記載されたコマンドを一括実行します。\r\n"
                      + "必要であればこの時点で編集してください。OKを押すと処理を開始します。",
                      "バッチ処理", MessageBoxButtons.OKCancel, MessageBoxIcon.Asterisk);
                    if (result == DialogResult.OK)
                        if (result == DialogResult.OK)
                            RunVolatilityBatch();
                        else
                            cmbCategory.SelectedIndex = 0;
                    return;
                }
            }
            // Windowsプロファイルの場合
            else
            {
                if ((string)cmbCategory.SelectedItem == "プロセス/DLL")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "pslist",
                        "pstree",
                        "psscan",
                        "dlllist",
                        "dlldump",
                        "handles",
                        "getsids",
                        "cmdscan",
                        "consoles",
                        "privs",
                        "envars",
                        "verinfo"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "プロセスメモリ")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "memmap",
                        "memdump",
                        "procdump",
                        "vadinfo",
                        "vadwalk",
                        "vadtree",
                        "vaddump",
                        "evtlogs",
                        "iehistory"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "カーネルメモリ/オブジェクト")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "modules",
                        "modscan",
                        "moddump",
                        "ssdt",
                        "driverscan",
                        "filescan",
                        "mutantscan",
                        "symlinkscan",
                        "thrdscan",
                        "dumpfiles",
                        "unloadedmodules",
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "レジストリ")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "hivelist",
                        "printkey",
                        "hivedump",
                        "hashdump",
                        "lsadump",
                        "userassist",
                        "shimcache",
                        "getservicesids",
                        "dumpregistry",
                        "amcache",
                        "auditpol",
                        "cachedump",
                        "shellbags",
                        "shutdowntime"
                      });
                }
                else if ((string)cmbCategory.SelectedItem == "ネットワーク")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "connections",
                        "connscan",
                        "sockets",
                        "sockscan",
                        "netscan"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "ファイルシステム")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "mbrparser",
                        "mftparser"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "マルウェア")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "malfind",
                        "yarascan",
                        "svcscan",
                        "ldrmodules",
                        "impscan",
                        "apihooks",
                        "idt",
                        "gdt",
                        "threads",
                        "callbacks",
                        "driverirp",
                        "devicetree",
                        "psxview",
                        "timers",
                        "servicediff"
                      });
                }
                else if ((string)cmbCategory.SelectedItem == "Windows GUI")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "sessions",
                        "wndscan",
                        "deskscan",
                        "atomscan",
                        "atoms",
                        "clipboard",
                        "eventhooks",
                        "gahti",
                        "messagehooks",
                        "userhandles",
                        "screenshot",
                        "gditimers",
                        "windows",
                        "wintree"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "その他")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "strings",
                        "bioskbd",
                        "patcher",
                        "timeliner",
                        "bigpools",
                        "cmdline",
                        "drivermodule",
                        "dumpcerts",
                        "editbox",
                        "joblinks",
                        "multiscan",
                        "notepad",
                        "objtypescan",
                        "poolpeek",
                        "pooltracker",
                        "truecryptmaster",
                        "truecryptpassphrase",
                        "truecryptsummary",
                        "win10cookie"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "イメージスキャン/変換")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "imageinfo",
                        "kdbgscan",
                        "kpcrscan",
                        "crashinfo",
                        "hibinfo",
                        "imagecopy",
                        "raw2dmp",
                        "vboxinfo",
                        "vmwareinfo",
                        "hpakinfo",
                        "hpakextract",
                        "qemuinfo"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "コミュニティ")
                {
                    cmbCommand.Items.AddRange(new object[] {
                        "agtidconfig",
                        "apihooksdeep",
                        "apt17scan",
                        "attributeht",
                        "autoruns",
                        "bitlocker",
                        "bitlocker10",
                        "callstacks",
                        "darkcometconfigdump",
                        "derusbiconfig",
                        "directoryenumerator",
                        "driverbl",
                        "dyrescan",
                        "exhistory",
                        "facebookcontacts",
                        "facebookgrabinfo",
                        "facebookmessages",
                        "firefoxcookies",
                        "firefoxdownloads",
                        "firefoxhistory",
                        "fwhooks",
                        "ghostrat",
                        "hikitconfig",
                        "hollowfind",
                        "hpv_clipboard",
                        "hpv_vmconnect",
                        "hpv_vmwp",
                        "idxparser",
                        "indx",
                        "javaratscan",
                        "lastpass",
                        "linuxgetprofile",
                        "logfile",
                        "malfinddeep",
                        "malfofind",
                        "malprocfind",
                        "malthfind",
                        "malsysproc",
                        "ndispktscan",
                        "networkpackets",
                        "openvpn",
                        "pdblist",
                        "plugxconfig",
                        "plugxscan",
                        "prefetchparser",
                        "processbl",
                        "profilescan",
                        "psinfo",
                        "redleavesconfig",
                        "redleavesscan",
                        "schtasks",
                        "sdbscanner",
                        "servicebl",
                        "shimcachemem",
                        "systeminfo",
                        "uninstallinfo",
                        "usbstor",
                        "usnjrnl",
                        "usnparser",
                        "zbotscan"
                    });
                }
                else if ((string)cmbCategory.SelectedItem == "バッチ処理")
                {
                    DialogResult result = MessageBox.Show(this, "conf\\batch_windows.txtに記載されたコマンドを一括実行します。\r\n"
                      + "必要であればこの時点で編集してください。OKを押すと処理を開始します。",
                      "バッチ処理", MessageBoxButtons.OKCancel, MessageBoxIcon.Asterisk);
                    if (result == DialogResult.OK)
                        RunVolatilityBatch();
                    else
                        cmbCategory.SelectedIndex = 0;
                    return;
                }
            }
            cmbCommand.SelectedIndex = 0;
            buildCommandline(sender, e);
            btnRun.Enabled = true;
        }

        // コマンド項目変更時
        private void comboBox3_SelectedIndexChanged(object sender, EventArgs e)
        {
            buildCommandline(sender, e);
            btnCmdHelp.Enabled = true;
        }

        // helpボタン実行時
        private void btnCmdHelp_Click(object sender, EventArgs e)
        {
            string origCommand;
            origCommand = txtCommandLine.Text;

            if ((string)cmbCategory.SelectedItem == "コミュニティ")
                txtCommandLine.Text = $"--plugins=community {cmbCommand.SelectedItem} -h";
            else
                txtCommandLine.Text = $"{cmbCommand.SelectedItem} -h";
            txtStdOutput.Text = "> volatility.exe " + txtCommandLine.Text + "\r\n";
            RunVolatilityStdout();
            txtCommandLine.Text = origCommand;
        }

        // タイムゾーンのチェックボックスクリック時
        private void chkJST_Click(object sender, EventArgs e)
        {
            buildCommandline(sender, e);
        }

        // プラグインのチェックボックスクリック時
        private void chkPlugins_Click(object sender, EventArgs e)
        {
            if (chkPlugins.Checked == true)
            {
                cmbCategory.Enabled = false;
                cmbCommand.Enabled = false;
                btnCmdHelp.Enabled = false;
                buildCommandline(sender, e);
            }
            else
            {
                cmbCategory.Enabled = true;
                cmbCommand.Enabled = true;
                btnCmdHelp.Enabled = true;
                buildCommandline(sender, e);
                comboBox3_SelectedIndexChanged(sender, e);
            }
        }

        // 実行/キャンセルボタンクリック時
        private void Run_Click(object sender, EventArgs e)
        {

            if (btnRun.Text == "実行")
            {
                // コントロール類を無効化
                txtInput.Enabled = false;
                btnInput.Enabled = false;
                txtOutput.Enabled = false;
                btnOutput.Enabled = false;
                cmbProfile.Enabled = false;
                cmbCategory.Enabled = false;
                cmbCommand.Enabled = false;
                chkAutoSave.Enabled = false;
                chkStdOut.Enabled = false;
                chkJST.Enabled = false;
                chkPlugins.Enabled = false;
                txtCommandLine.Enabled = false;

                btnRun.Text = "キャンセル";

                // あらかじめ動いていたvolatilitlyプロセスのチェック
                Process[] ps = Process.GetProcessesByName("volatility");
                foreach (Process p in ps)
                {
                    KnownId.Add(p.Id);
                }

                // 自動保存有効かつ出力フォルダに指定されたフォルダが存在しない場合は作成      
                if (chkAutoSave.Checked)
                {
                    if (Directory.Exists(txtOutput.Text) == false)
                        Directory.CreateDirectory(txtOutput.Text);

                    // 自動保存有効かつ-Dオプションで指定されたフォルダが存在しなければ作成
                    StreamReader file = new StreamReader(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\conf\dumpcmd.txt", System.Text.Encoding.Default);
                    bool dmpCmd;
                    dmpCmd = false;
                    string line;

                    while (file.Peek() >= 0)
                    {
                        line = file.ReadLine();
                        if (line.StartsWith("//"))
                            continue;
                        if (cmbCommand.Text == line)
                        {
                            dmpCmd = true;
                            break;
                        }
                    }
                    file.Close();

                    if (dmpCmd)
                    {
                        if (Directory.Exists(txtOutput.Text + @"\" + cmbCommand.Text) == false)
                            Directory.CreateDirectory(txtOutput.Text + @"\" + cmbCommand.Text);
                    }
                }

                if (backgroundWorker1.IsBusy == false)
                {
                    txtStdOutput.Text = "> volatility.exe " + txtCommandLine.Text + "\r\n";
                    progressBar1.Style = ProgressBarStyle.Marquee;
                    progressBar1.MarqueeAnimationSpeed = 30;
                    backgroundWorker1.RunWorkerAsync();
                }
            }
            else // キャンセル時
            {
                // 動作中のvolatilitlyプロセス情報を取得
                Process[] ps = Process.GetProcessesByName("volatility");
                // KaniVola経由で起動したプロセスのみを停止
                foreach (Process p in ps)
                {
                    if (KnownId.Contains(p.Id) != true)
                        p.Kill();
                }
                System.Threading.Thread.Sleep(1500);
                // バッチ処理時
                if (cmbCategory.Text.Contains("バッチ処理"))
                    backgroundWorker2.CancelAsync();
                // 通常実行時
                else
                    backgroundWorker1.CancelAsync();
            }
        }

        // バックグラウンドメイン処理用(DoWork)
        private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                process1.StartInfo.Arguments = txtCommandLine.Text;  // 引数
                process1.Start();
                string commandOutputStd, commandErrStd;
                commandOutputStd = process1.StandardOutput.ReadToEnd();
                commandErrStd = process1.StandardError.ReadToEnd();

                // キャンセルされてないか定期的にチェック
                if (backgroundWorker2.CancellationPending)
                {
                    e.Cancel = true;
                    return;
                }

                process1.WaitForExit(60000); // 最大1分待機

                // 標準エラー出力、標準出力の順に表示
                e.Result = commandErrStd + "\r\n" + commandOutputStd;
            }
            catch
            {
                MessageBox.Show("エラーが発生しました。KaniVolaを再起動してください。");
            }
        }

        // バックグラウンド進捗バー制御用(何もしていない)
        private void backgroundWorker1_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            progressBar1.Value = e.ProgressPercentage;
        }

        // バックグラウンドメイン処理終了時の後処理
        private void backgroundWorker1_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            progressBar1.Style = ProgressBarStyle.Blocks;
            progressBar1.Value = 0;
            btnRun.Text = "実行";
            txtStdOutput.SelectionStart = txtStdOutput.Text.Length;
            txtStdOutput.Focus();
            txtStdOutput.ScrollToCaret();

            if (chkStdOut.Checked)
                txtStdOutput.Text += e.Result;

            if (e.Result.ToString().Length == 0)
                txtStdOutput.Text += "結果はありませんでした。";

            if (e.Cancelled)
            {
                txtStdOutput.Text += "中断\r\n";
            }

            // 自動保存有効時はコマンド名でファイルを保存
            if (chkAutoSave.Checked)
            {
                string outFile;
                if (chkPlugins.Checked)
                    outFile = txtOutput.Text + @"\plugins.txt";
                else
                    outFile = txtOutput.Text + @"\" + cmbCommand.Text + ".txt";
                StreamWriter sw = new StreamWriter(outFile, false, System.Text.Encoding.GetEncoding("utf-8"));
                sw.Write(e.Result);
                sw.Close();
            }

            // コントロール類を有効化状態に戻す
            txtInput.Enabled = true;
            btnInput.Enabled = true;
            txtOutput.Enabled = true;
            btnOutput.Enabled = true;
            cmbProfile.Enabled = true;
            if (chkPlugins.Checked == false)
            {
                cmbCategory.Enabled = true;
                cmbCommand.Enabled = true;
            }
            chkAutoSave.Enabled = true;
            chkStdOut.Enabled = true;
            chkJST.Enabled = true;
            txtCommandLine.Enabled = true;
            btnRun.Enabled = true;
            if (!cmbProfile.Text.Contains("Linux") && !cmbProfile.Text.Contains("Mac"))
                chkPlugins.Enabled = true;

        }

        // volatitliy.exe実行&ファイル保存
        private void RunVolatilityFile(string command)
        {
            // コマンド名でファイルを保存
            string outFile = txtOutput.Text + @"\" + command + ".txt";
            StreamWriter sw = new StreamWriter(outFile, false, System.Text.Encoding.GetEncoding("utf-8"));
            process1.Start();
            sw.Write(process1.StandardOutput.ReadToEnd());
            sw.Close();

            process1.StandardError.ReadLine();
            string lineString;
            lineString = process1.StandardError.ReadLine();
            // 1行目の出力はスキップしてその他にエラーがあれば保存
            if (lineString != null)
            {
                string outErrFile = txtOutput.Text + @"\error\" + command + ".txt";
                StreamWriter swErr = new StreamWriter(outErrFile, false, System.Text.Encoding.GetEncoding("utf-8"));
                swErr.WriteLine(lineString);
                while ((lineString = process1.StandardError.ReadLine()) != null)
                    swErr.WriteLine(lineString);
                swErr.Close();
            }
            process1.WaitForExit(60000); // 最大1分待機
        }

        // volatitliy.exe実行&標準出力(兼help/info用)
        private void RunVolatilityStdout()
        {
            process1.StartInfo.Arguments = txtCommandLine.Text; // 引数
            process1.Start();

            if (txtCommandLine.Text.Contains(" --info"))
            {
                string lineString, profileName;
                int i;
                cmbProfile.Items.Clear();
                string line = "";
                StreamReader profFile = new StreamReader(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\conf\profiles.txt", System.Text.Encoding.Default);

                while (profFile.Peek() >= 0)
                {
                    line = profFile.ReadLine();
                    if (line.StartsWith("//"))
                        continue;

                    cmbProfile.Items.Add(line);
                }
                cmbProfile.Items.Add("Linux/Mac");

                while ((lineString = process1.StandardOutput.ReadLine()) != null)
                {
                    if (lineString.Contains("Profile") && (lineString.Contains("Linux") || lineString.Contains("Mac")))
                    {
                        txtStdOutput.Text += lineString + "\r\n";
                        i = lineString.IndexOf(" ");
                        if (i > 0)
                        {
                            profileName = lineString.Substring(0, i);
                            cmbProfile.Items.AddRange(new object[] { profileName });
                        }
                    }
                }
            }
            else
            {
                txtStdOutput.Text += process1.StandardOutput.ReadToEnd() + "\r\n";
            }
            txtStdOutput.SelectionStart = txtStdOutput.Text.Length;
            txtStdOutput.Focus();
            txtStdOutput.ScrollToCaret();
            process1.WaitForExit(60000); // 最大1分待機
        }

        // バッチ実行時
        private void RunVolatilityBatch()
        {

            String[] array = new String[3];
            array[0] = cmbProfile.SelectedItem.ToString();
            array[1] = txtInput.Text;
            array[2] = txtOutput.Text;

            // 保存先フォルダに指定されたフォルダが存在しない場合は作成      
            if (!Directory.Exists(txtOutput.Text))
                Directory.CreateDirectory(txtOutput.Text);

            if (!Directory.Exists(txtOutput.Text + @"\error"))
                Directory.CreateDirectory(txtOutput.Text + @"\error");

            // コントロール類を無効化
            txtInput.Enabled = false;
            btnInput.Enabled = false;
            txtOutput.Enabled = false;
            btnOutput.Enabled = false;
            cmbProfile.Enabled = false;
            cmbCategory.Enabled = false;
            cmbCommand.Enabled = false;
            chkAutoSave.Enabled = false;
            chkStdOut.Enabled = false;
            chkJST.Enabled = false;
            chkPlugins.Enabled = false;
            txtCommandLine.Enabled = false;

            btnRun.Text = "キャンセル";
            txtStdOutput.Text = "";
            progressBar1.Style = ProgressBarStyle.Marquee;
            progressBar1.MarqueeAnimationSpeed = 30;
            backgroundWorker2.RunWorkerAsync(array);
        }

        // バッチ処理用バックグラウンド処理
        private void backgroundWorker2_DoWork(object sender, DoWorkEventArgs e)
        {

            // 進捗バー用カウンタ
            int curNum, numOfCmd;
            String[] strArg = (String[])e.Argument;
            curNum = 0;

            List<string> cmdList = new List<string>();
            string batchFile;

            if (strArg[0].Contains("Linux"))
                batchFile = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\conf\batch_linux.txt";
            else if (strArg[0].Contains("Mac"))
                batchFile = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\conf\batch_macosx.txt";
            else
                batchFile = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\conf\batch_windows.txt";

            StreamReader cmdFile = new StreamReader(batchFile, System.Text.Encoding.Default);

            string line = "";

            while (cmdFile.Peek() >= 0)
            {
                line = cmdFile.ReadLine();
                if (line.StartsWith("//"))
                    continue;
                cmdList.Add(line);
            }
            cmdFile.Close();

            numOfCmd = cmdList.Count;

            foreach (string command in cmdList)
            {
                // キャンセルされてないか定期的にチェック
                if (backgroundWorker2.CancellationPending)
                {
                    e.Cancel = true;
                    return;
                }

                if (strArg[0].Contains("Linux") || strArg[0].Contains("Mac"))
                    process1.StartInfo.Arguments = $"--plugins=profiles;community --profile={strArg[0]} -f \"{strArg[1]}\" {command}";
                else // Windows
                    process1.StartInfo.Arguments = $"--plugins=community --profile={strArg[0]} -f \"{strArg[1]}\" {command}";

                StreamReader dmpFile = new StreamReader(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\conf\dumpcmd.txt", System.Text.Encoding.Default);
                bool dmpCmd;
                int pos;
                string command_name;
                dmpCmd = false;
                pos = command.IndexOf(" ");
                if (pos > 0)
                    command_name = command.Substring(0, pos);
                else
                    command_name = command;

                while (dmpFile.Peek() >= 0)
                {
                    line = dmpFile.ReadLine();
                    if (line.StartsWith("//"))
                        continue;

                    if (command_name == line)
                    {
                        dmpCmd = true;
                        break;
                    }
                }
                dmpFile.Close();

                if (dmpCmd)
                {
                    process1.StartInfo.Arguments += $" -D \"{strArg[2]}\\{command}\"";
                    if (!Directory.Exists($"{txtOutput.Text}\\{command}"))
                        Directory.CreateDirectory($"{txtOutput.Text}\\{command}");
                }

                if (chkJST.Checked == true)
                    process1.StartInfo.Arguments += " --tz=Asia/Tokyo";

                backgroundWorker2.ReportProgress((curNum * 100) / numOfCmd);
                RunVolatilityFile(command);
                ++curNum;
            }
        }

        // バッチ処理用進捗表示
        private void backgroundWorker2_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            txtStdOutput.Text += $"> volatility.exe {process1.StartInfo.Arguments} ({e.ProgressPercentage}%)" + "\r\n";
            txtStdOutput.SelectionStart = txtStdOutput.Text.Length;
            txtStdOutput.Focus();
            txtStdOutput.ScrollToCaret();
        }

        // ツール > AFF4変換
        private void aff4ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            openFileDialog.Filter = "AFF4形式|*.aff4";
            if (DialogResult.OK == openFileDialog.ShowDialog())
            {

                DialogResult result = MessageBox.Show("RAW形式に変換します。変換後のファイルは同じ場所に拡張子をrawにして出力します。", "確認", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
                if (result == DialogResult.Yes)
                {
                    process2.StartInfo.FileName = Directory.GetCurrentDirectory() + "\\winpmem.exe";
                    process2.StartInfo.WorkingDirectory = Path.GetDirectoryName(openFileDialog.FileName);
                    process2.StartInfo.Arguments = $"-e PhysicalMemory -o {Path.GetFileNameWithoutExtension(openFileDialog.FileName)}.raw {openFileDialog.FileName}";
                    process2.Start();
                    process2.WaitForExit(1800000);
                    if (process2.ExitCode == 0)
                        MessageBox.Show("変換が完了しました。", "完了", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    else
                        MessageBox.Show("エラーが発生しました。AFF4形式のファイルを指定してください。", "完了", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    cmbCommand.SelectedIndex = 0;
                    return;
                }
            }
            openFileDialog.Filter = "";
        }

        // ヘルプ > バージョン情報
        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Form f = new KaniVola.about();
            f.ShowDialog(this);
            f.Dispose();
        }

        // バッチ処理終了時
        private void backgroundWorker2_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            txtInput.Enabled = true;
            btnInput.Enabled = true;
            txtOutput.Enabled = true;
            btnOutput.Enabled = true;
            cmbProfile.Enabled = true;
            cmbCategory.Enabled = true;
            cmbCategory.SelectedIndex = 0;
            cmbCommand.Enabled = true;
            chkAutoSave.Enabled = true;
            chkStdOut.Enabled = true;
            chkJST.Enabled = true;
            txtCommandLine.Enabled = true;
            btnRun.Enabled = true;
            if (!cmbProfile.Text.Contains("Linux") && !cmbProfile.Text.Contains("Mac"))
                chkPlugins.Enabled = true;

            progressBar1.Style = ProgressBarStyle.Blocks;
            progressBar1.Value = 0;
            btnRun.Text = "実行";
            txtStdOutput.SelectionStart = txtStdOutput.Text.Length;
            txtStdOutput.Focus();
            txtStdOutput.ScrollToCaret();

            if (e.Cancelled)
            {
                MessageBox.Show(this, "キャンセルしました", "バッチ処理", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                txtStdOutput.Text += "中断\r\n";
            }
            else
            {
                MessageBox.Show(this, "終了しました", "バッチ処理", MessageBoxButtons.OK, MessageBoxIcon.Information);
                txtStdOutput.Text += "バッチ処理完了 (100%)\r\n";
            }
        }

        private void buildCommandline(object sender, EventArgs e)
        {
            string optPlugins, optTZ, optProfile, optInput, optCommand, optDump;

            // --plugins
            if (chkPlugins.Checked)
            {
                optPlugins = $"--plugins=plugins";
            }
            else if (cmbProfile.SelectedItem == null)
            {
                optPlugins = "";
            }
            else if ( (cmbProfile.SelectedItem.ToString().Contains("Linux") == true || cmbProfile.SelectedItem.ToString().Contains("Mac") == true)
                && (string)cmbCategory.SelectedItem == "コミュニティ")
            {
                optPlugins = $"--plugins=profiles;community";
            }
            else if (cmbProfile.SelectedItem.ToString().Contains("Linux") == true
                || cmbProfile.SelectedItem.ToString().Contains("Mac") == true)
            {
                optPlugins = $"--plugins=profiles";
            }
            else if ((string)cmbCategory.SelectedItem == "コミュニティ")
            {
                optPlugins = $"--plugins=community";
            }
            else
                optPlugins = "";

            // --tz
            if (chkJST.Checked)
                optTZ = $"--tz=Asia/Tokyo";
            else
                optTZ = "";

            // --profile
            if (cmbProfile.SelectedItem == null)
                optProfile = "";
            else
                optProfile = $"--profile={cmbProfile.SelectedItem}";

            // -f
            if (txtInput.Text == null || txtInput.Text == "")
                optInput = "";
            else
                optInput = $"-f \"{txtInput.Text}\"";

            // command
            if (cmbCommand.SelectedItem == null || cmbCommand.Enabled == false)
                optCommand = "";
            else
                optCommand = $"{cmbCommand.Text}";
            //                optCommand = $"{cmbCommand.SelectedItem}";

            // -D
            StreamReader dmpFile = new StreamReader(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\conf\dumpcmd.txt", System.Text.Encoding.Default);
            optDump = "";
            while (dmpFile.Peek() >= 0)
            {
                if (cmbCommand.Text == dmpFile.ReadLine())
                {
                    optDump = $"-D \"{txtOutput.Text}\\{cmbCommand.Text}\"";
                    break;
                }
            }
            dmpFile.Close();

            // -O
            if (cmbCommand.Text == "imagecopy")
                optDump = $"-O \"{txtOutput.Text}\\{Path.GetFileNameWithoutExtension(txtInput.Text)}.raw\"";
            if (cmbCommand.Text == "raw2dmp")
                optDump = $"-O \"{txtOutput.Text}\\{Path.GetFileNameWithoutExtension(txtInput.Text)}.dmp\"";

            // build
            txtCommandLine.Text = $"{optPlugins} {optTZ} {optProfile} {optInput} {optCommand} {optDump}";
        }

        private void Form1_Load(object sender, EventArgs e)
        {
        }


    }
}

