using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;


namespace KaniVolatility {

  public partial class Form1 : Form {
    static public List<int> KnownId = new List<int>();   // プロセス停止チェック用
    static public string PrevInputFileName, PrevProfileName, PrevOutputDumpFolderName; //  対象ファイル、プロファイル、出力フォルダ(ダンプ用)の控え
    public Form1() {
      InitializeComponent();
      cmbProfile.Enabled = false;
      cmbCategory.Enabled = false;
      cmbCommand.Enabled = false;
      btnCmdHelp.Enabled = false;
      btnRun.Enabled = false;
      btnOutput.Enabled = false;
      if (!File.Exists("volatility.exe")) {
        MessageBox.Show("volatilityプログラムが存在しません。\r\n\r\n"        
          + "公式サイト(http://www.volatilityfoundation.org/)からスタンドアロン版の"
          + "Windowsプログラム(Volatility 2.4 Windows Standalone Executable)を入手してください。\r\n\r\n"
          + "入手したファイルのファイル名をvolatility.exeに変更してから"
          + "KaniVolatility.exeと同じフォルダに配置し、再度実行してください。",
          "実行エラー");
        Environment.Exit(0);
      }

      cmbCategory.Items.Add("イメージスキャン/変換"); // 初期選択可能カテゴリ
      cmbCategory.SelectedIndex = 0;
    
    }

    // 対象ファイルの選択ボタンクリック時
    private void buttonInputFile_Click(object sender, EventArgs e) {
      if (DialogResult.OK == openFileDialog.ShowDialog()) { // 選択されれば値追加、有効化等の処理
        txtBoxInput.Text = openFileDialog.FileName;
        if (Path.GetDirectoryName(txtBoxInput.Text).EndsWith("\\") == true)
          txtOutput.Text = Path.GetDirectoryName(txtBoxInput.Text) + Path.GetFileNameWithoutExtension(txtBoxInput.Text) + "_Output";
        else
          txtOutput.Text = Path.GetDirectoryName(txtBoxInput.Text) + "\\" + Path.GetFileNameWithoutExtension(txtBoxInput.Text) + "_Output";

        cmbProfile.Enabled = true;
        cmbCommand.SelectedIndex = 0;
        cmbCommand.Enabled = true;
        btnOutput.Enabled = true;
        btnRun.Enabled = true;

        // 実行コマンド欄への反映
        if (PrevInputFileName == null)
          txtCommandLine.Text = " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.SelectedItem;
        else
          txtCommandLine.Text = txtCommandLine.Text.Replace(PrevInputFileName, txtBoxInput.Text);

        PrevInputFileName = txtBoxInput.Text;
      }
    }

    // 対象ファイルのテキストボックスへのドラッグ&ドロップ用
    private void textBoxInput_DragDrop(object sender, DragEventArgs e) {
      string[] data = (string[])e.Data.GetData("FileDrop", false);
      if (File.Exists(data[0])) { // ファイルが投入されれば値追加、有効化等の処理
        txtBoxInput.Text = data[0];
        if (Path.GetDirectoryName(txtBoxInput.Text).EndsWith("\\") == true)
          txtOutput.Text = Path.GetDirectoryName(txtBoxInput.Text) + Path.GetFileNameWithoutExtension(txtBoxInput.Text) + "_Output";
        else
          txtOutput.Text = Path.GetDirectoryName(txtBoxInput.Text) + "\\" + Path.GetFileNameWithoutExtension(txtBoxInput.Text) + "_Output";

        cmbProfile.Enabled = true;
        cmbCommand.SelectedIndex = 0;
        cmbCommand.Enabled = true;
        btnOutput.Enabled = true;
        btnRun.Enabled = true;

        // 実行コマンド欄への反映
        if (PrevInputFileName == null)
          txtCommandLine.Text = " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.SelectedItem;
        else
          txtCommandLine.Text = txtCommandLine.Text.Replace(PrevInputFileName, txtBoxInput.Text);

        PrevInputFileName = txtBoxInput.Text;
      }
    }

    // 対象ファイル&出力フォルダのテキストボックスへのドラッグ&ドロップ用
    private void textBox_DragEnter(object sender, DragEventArgs e) {
      if (e.Data.GetDataPresent(DataFormats.FileDrop))
        e.Effect = DragDropEffects.All;
      else
        e.Effect = DragDropEffects.None;
    }

    // 出力フォルダの選択ボタンクリック時
    private void buttonOutput_Click(object sender, EventArgs e) {
      if (DialogResult.OK == folderBrowserDialogOutput.ShowDialog()) {
        txtOutput.Text = folderBrowserDialogOutput.SelectedPath;
      }

      // 実行コマンド欄に-Dオプションが含まれていた場合は更新
      if (txtCommandLine.Text.Contains("-D ")) {
        if (PrevOutputDumpFolderName != null) {
          txtCommandLine.Text = txtCommandLine.Text.Replace(PrevOutputDumpFolderName, txtOutput.Text + "\\" + cmbCommand.SelectedItem);
          PrevOutputDumpFolderName = txtOutput.Text + "\\" + cmbCommand.SelectedItem;
        }
      }
    }

    // 出力フォルダのテキストボックスへのドラッグ&ドロップ用
    private void textBoxOutput_DragDrop(object sender, DragEventArgs e) {
      string[] data = (string[])e.Data.GetData("FileDrop", false);
      if (Directory.Exists(data[0])) {
        String[] files = Directory.GetFiles(data[0], "*");
        txtOutput.Text = data[0];
        // 実行コマンド欄に-Dオプションが含まれていた場合は更新
        if (txtCommandLine.Text.Contains("-D ")) {
          if (PrevOutputDumpFolderName != null) {
            txtCommandLine.Text = txtCommandLine.Text.Replace(PrevOutputDumpFolderName, txtOutput.Text + "\\" + cmbCommand.SelectedItem);
            PrevOutputDumpFolderName = txtOutput.Text + "\\" + cmbCommand.SelectedItem;
          }
        }
      }
    }
    
    // プロファイル項目選択時
    private void cmbProfile_SelectedIndexChanged(object sender, EventArgs e) {
      if (cmbProfile.SelectedItem.ToString() == "Linux/Mac") {
        DialogResult result = MessageBox.Show(this, "KaniVolatility.exeがある場所にprofilesフォルダを作成してください。"
          + "そのフォルダ配下に追加対象プロファイル(zip形式)を配置してからOKボタンを押してください。"
          + "認識したプロファイルを一覧に追加します。", 
          "プロファイルの追加", MessageBoxButtons.OKCancel, MessageBoxIcon.Asterisk);
        if (result == DialogResult.OK) {
          txtCommandLine.Text = "--plugins=profiles --info";
          txtStdOutput.Text = "> volatility.exe " + txtCommandLine.Text + "\r\n";
          RunVolatilityStdout();
          cmbCategory.Items.Clear();
          cmbCommand.Items.Clear();
        }
        return;
      }
      else if (cmbProfile.SelectedItem.ToString().Contains("Linux") == true) {
        // プロファイルが新規または別OSからLinuxに変更された場合はカテゴリリストを再作成
        if (PrevProfileName == null || 
          PrevProfileName.Contains("Win") == true || 
          PrevProfileName.Contains("Vista") == true ||
          PrevProfileName.Contains("Mac") == true) {
          cmbCategory.Items.Clear();
          cmbCategory.Items.AddRange(new object[] {
            "プロセス", 
            "プロセスメモリ", 
            "カーネルメモリ/オブジェクト", 
            "ネットワーク", 
            "マルウェア", 
            "システム情報", 
            "その他", 
            "イメージスキャン/変換"
          });
          txtCommandLine.Text = "--plugins=profiles --profile=" + cmbProfile.SelectedItem + " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.SelectedItem;
          cmbCommand.Items.Clear();
        }
        else {
          txtCommandLine.Text = txtCommandLine.Text.Replace(PrevProfileName, cmbProfile.Text);
        }
      }
      else if (cmbProfile.SelectedItem.ToString().Contains("Mac") == true) {
        // プロファイルが新規または別OSからMacに変更された場合はカテゴリリストを再作成(Linux変更時と同じ処理)
        if (PrevProfileName == null || PrevProfileName.Contains("Win") == true || PrevProfileName.Contains("Vista") == true || PrevProfileName.Contains("Linux") == true) {
          cmbCategory.Items.Clear();
          cmbCategory.Items.AddRange(new object[] {
            "プロセス", 
            "プロセスメモリ", 
            "カーネルメモリ/オブジェクト", 
            "ネットワーク", 
            "マルウェア", 
            "システム情報", 
            "その他", 
            "イメージスキャン/変換"
          });
          txtCommandLine.Text = "--plugins=profiles --profile=" + cmbProfile.SelectedItem + " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.SelectedItem;
          cmbCommand.Items.Clear();
        }
        else {
          txtCommandLine.Text = txtCommandLine.Text.Replace(PrevProfileName, cmbProfile.Text);
        }
      } 
      // Windows用
      else {
        // プロファイルが新規に選択された場合は現在の状態を維持しつつカテゴリリストを作成
        if (PrevProfileName == null) {
          int i = cmbCommand.SelectedIndex; // 選択されていたコマンド情報を保持
          txtCommandLine.Text = "--profile=" + cmbProfile.SelectedItem + " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.SelectedItem;
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
            "イメージスキャン/変換"
          });
          cmbCategory.SelectedIndex = 9; // イメージスキャン/変換
          cmbCommand.SelectedIndex = i; // 保持していた情報に戻す
        }
        // プロファイルが別OSからWinに変更された場合はカテゴリリストを再作成
        else if (PrevProfileName.Contains("Mac") == true || PrevProfileName.Contains("Linux") == true) {
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
            "イメージスキャン/変換"
          });
          txtCommandLine.Text = "--profile=" + cmbProfile.SelectedItem + " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.SelectedItem;
          cmbCommand.Items.Clear();
        }
        else {
          txtCommandLine.Text = txtCommandLine.Text.Replace(PrevProfileName, cmbProfile.Text);
        }
      }
      cmbCategory.Enabled = true;
      PrevProfileName = cmbProfile.Text;
    }

    // カテゴリ項目選択時
    private void comboBox2_SelectedIndexChanged(object sender, EventArgs e) {
      cmbCommand.Items.Clear();
      if (cmbCategory.SelectedIndex == 0 && (string)cmbCategory.SelectedItem == "イメージスキャン/変換") {
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
          "hpakextract"
        });
        return;
      }
      // Linuxプロファイルの場合
      else if (cmbProfile.SelectedItem.ToString().Contains("Linux") == true) {
        if ((string)cmbCategory.SelectedItem == "プロセス") {
          cmbCommand.Items.AddRange(new object[] {
            "linux_pslist", 
            "linux_psaux", 
            "linux_pstree", 
            "linux_pslist_cache", 
            "linux_pidhashtable", 
            "linux_psxview", 
            "linux_lsof", 
            "linux_psenv", 
            "linux_threads"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "プロセスメモリ") {
          cmbCommand.Items.AddRange(new object[] {
            "linux_memmap", 
            "linux_proc_maps", 
            "linux_dump_map", 
            "linux_bash", 
            "linux_bash_env", 
            "linux_bash_hash",
            "linux_elfs", 
            "linux_library_list", 
            "linux_librarydump", 
            "linux_proc_maps_rb", 
            "linux_procdump"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "カーネルメモリ/オブジェクト") {
          cmbCommand.Items.AddRange(new object[] {
            "linux_lsmod", 
            "linux_moddump", 
            "linux_tmpfs", 
            "linux_hidden_modules", 
            "linux_info_regs", 
            "linux_kernel_opened_files"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "ネットワーク") {
          cmbCommand.Items.AddRange(new object[] {
            "linux_arp", 
            "linux_ifconfig", 
            "linux_route_cache", 
            "linux_netstat", 
            "linux_pkt_queues", 
            "linux_sk_buff_cache", 
            "linux_list_raw"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "マルウェア") {
          cmbCommand.Items.AddRange(new object[] {
            "linux_malfind", 
            "linux_apihooks", 
            "linux_check_afinfo", 
            "linux_check_inline_kernel", 
            "linux_check_tty", 
            "linux_keyboard_notifiers", 
            "linux_check_creds", 
            "linux_check_fop", 
            "linux_check_idt", 
            "linux_check_syscall", 
            "linux_check_modules", 
            "linux_ldrmodules", 
            "linux_netfilter", 
            "linux_plthook", 
            "linux_process_hollow"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "システム情報") {
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
            "linux_enumerate_files"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "その他") {
          cmbCommand.Items.AddRange(new object[] {
            "linux_yarascan", 
            "linux_recover_filesystem", 
            "linux_strings", 
            "linux_truecrypt_passphrase"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "イメージスキャン/変換") {
          cmbCommand.Items.AddRange(new object[] {
            "imagecopy", 
            "limeinfo", 
            "vboxinfo", 
            "vmwareinfo", 
            "hpakinfo", 
            "hpakextract"
          });
        }
      } 
      // Macプロファイルの場合
      else if (cmbProfile.SelectedItem.ToString().Contains("Mac") == true) {
        if ((string)cmbCategory.SelectedItem == "プロセス") {
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
        else if ((string)cmbCategory.SelectedItem == "プロセスメモリ") {
          cmbCommand.Items.AddRange(new object[] {
            "mac_proc_maps", 
            "mac_dump_maps", 
            "mac_bash", 
            "mac_bash_env", 
            "mac_bash_hash", 
            "mac_memdump", 
            "mac_procdump"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "カーネルメモリ/オブジェクト") {
          cmbCommand.Items.AddRange(new object[] {
            "mac_list_sessions", 
            "mac_list_zones", 
            "mac_lsmod", 
            "mac_mount", 
            "mac_adium",
            "mac_dump_file", 
            "mac_dyld_maps", 
            "mac_librarydump", 
            "mac_list_files", 
            "mac_lsmod_iokit", 
            "mac_lsmod_kext_map", 
            "mac_moddump"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "ネットワーク") {
          cmbCommand.Items.AddRange(new object[] {
            "mac_arp", 
            "mac_ifconfig", 
            "mac_netstat", 
            "mac_route", 
            "mac_dead_sockets", 
            "mac_network_conns",
            "mac_socket_filters"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "マルウェア") {
          cmbCommand.Items.AddRange(new object[] {
            "mac_malfind", 
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
            "mac_ldrmodules"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "システム情報") {
          cmbCommand.Items.AddRange(new object[] {
            "mac_dmesg", 
            "mac_find_aslr_shift", 
            "mac_machine_info", 
            "mac_version", 
            "mac_print_boot_cmdline",
            "mac_dead_vnodes"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "その他") {
          cmbCommand.Items.AddRange(new object[] {
            "mac_yarascan", 
            "mac_calendar", 
            "mac_contacts", 
            "mac_keychaindump", 
            "mac_notesapp", 
            "mac_recover_filesystem", 
            "mac_strings"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "イメージスキャン/変換") {
          cmbCommand.Items.AddRange(new object[] {
            "imagecopy", 
            "vboxinfo", 
            "vmwareinfo", 
            "hpakinfo", 
            "hpakextract", 
            "machoinfo"
          });
        }
      }
      // Windowsプロファイルの場合
      else {
        if ((string)cmbCategory.SelectedItem == "プロセス/DLL") {
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
            "cmdline", 
            "joblinks"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "プロセスメモリ") {
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
        else if ((string)cmbCategory.SelectedItem == "カーネルメモリ/オブジェクト") {
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
            "bigpools",
            "multiscan", 
            "objtypescan", 
            "poolpeek", 
            "pooltracker"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "レジストリ") {
          cmbCommand.Items.AddRange(new object[] {
            "auditpol", 
            "hivelist", 
            "printkey", 
            "hivedump", 
            "hashdump", 
            "cachedump", 
            "lsadump",
            "userassist", 
            "shellbags", 
            "shimcache", 
            "getservicesids"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "ネットワーク") {
          cmbCommand.Items.AddRange(new object[] {
            "connections", 
            "connscan", 
            "sockets", 
            "sockscan", 
            "netscan"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "ファイルシステム") {
          cmbCommand.Items.AddRange(new object[] {
            "mbrparser", 
            "mftparser"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "マルウェア") {
          cmbCommand.Items.AddRange(new object[] {
            "malfind", 
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
            "verinfo"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "Windows GUI") {
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
            "screenshot", 
            "userhandles", 
            "windows", 
            "wintree", 
            "gditimers"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "その他") {
          cmbCommand.Items.AddRange(new object[] {
            "strings", 
            "bioskbd", 
            "patcher", 
            "timeliner", 
            "dumpcerts", 
            "notepad",
            "truecryptmaster", 
            "truecryptpassphrase", 
            "truecryptsummary"
          });
        }
        else if ((string)cmbCategory.SelectedItem == "イメージスキャン/変換") {
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
            "hpakextract"
          });
        }
      }
      cmbCommand.SelectedIndex = 0;
      if (cmbCategory.SelectedIndex == 0 && (string)cmbCategory.SelectedItem == "イメージスキャン/変換")
        return;
      else if (cmbProfile.SelectedItem.ToString().Contains("Mac") == true || cmbProfile.SelectedItem.ToString().Contains("Linux") == true) {
        txtCommandLine.Text = "--plugins=profiles --profile=" + cmbProfile.SelectedItem + " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.SelectedItem;
      }
      else {
        txtCommandLine.Text = "--profile=" + cmbProfile.SelectedItem + " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.SelectedItem;
      }
      btnRun.Enabled = true;
    }

    // コマンド項目選択時
    private void comboBox3_SelectedIndexChanged(object sender, EventArgs e) {

      if (cmbCategory.SelectedIndex == 0 && (string)cmbCategory.SelectedItem == "イメージスキャン/変換") {
        if (txtBoxInput.Text != "")
          txtCommandLine.Text = " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.Text;
        else
          txtCommandLine.Text = "";
      }
      else if (cmbProfile.SelectedItem.ToString().Contains("Linux") || cmbProfile.SelectedItem.ToString().Contains("Mac"))
        txtCommandLine.Text = "--plugins=profiles --profile=" + cmbProfile.SelectedItem + " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.Text;
      else
        txtCommandLine.Text = "--profile=" + cmbProfile.SelectedItem + " -f \"" + txtBoxInput.Text + "\" " + cmbCommand.Text;
      
      // ダンプするコマンドは-Dオプション項目を有効化(フォルダはコマンド名を想定)
      if (cmbCommand.Text == "dlldump" || 
        cmbCommand.Text == "dumpfiles" || 
        cmbCommand.Text == "evtlogs" || 
        cmbCommand.Text == "memdump" || 
        cmbCommand.Text == "moddump" ||
        cmbCommand.Text == "procdump" || 
        cmbCommand.Text == "truecryptmaster" || 
        cmbCommand.Text == "screenshot" || 
        cmbCommand.Text == "vaddump" || 
        cmbCommand.Text == "verinfo" || 
        cmbCommand.Text == "dumpcerts" || 
        cmbCommand.Text == "linux_dump_map" || 
        cmbCommand.Text == "linux_moddump" || 
        cmbCommand.Text == "linux_librarydump" ||
        cmbCommand.Text == "linux_procdump" || 
        cmbCommand.Text == "linux_recover_filesystem" ||
        cmbCommand.Text == "linux_sk_buff_cache" ||
        cmbCommand.Text == "linux_pkt_queues" ||
        cmbCommand.Text == "mac_adium" ||
        cmbCommand.Text == "mac_dump_maps" ||
        cmbCommand.Text == "mac_librarydump" || 
        cmbCommand.Text == "mac_memdump" || 
        cmbCommand.Text == "mac_moddump" || 
        cmbCommand.Text == "mac_notesapp" ||
        cmbCommand.Text == "mac_procdump" || 
        cmbCommand.Text == "mac_recover_filesystem")
      {
        chkAutoSave.Checked = true;
        txtDump.Enabled = true;
        txtDump.Text = cmbCommand.Text;
        txtCommandLine.Text += " -D \"" + txtOutput.Text + "\\" + txtDump.Text + "\"";
        PrevOutputDumpFolderName = txtOutput.Text + "\\" + txtDump.Text;
      }
      else if (cmbCommand.Text == "imagecopy") {
        chkAutoSave.Checked = true;
        txtCommandLine.Text += " -O \"" + txtOutput.Text + "\\" + Path.GetFileNameWithoutExtension(txtBoxInput.Text) + ".raw\"";
      }
      else if (cmbCommand.Text == "raw2dmp") {
        chkAutoSave.Checked = true;
        txtCommandLine.Text += " -O \"" + txtOutput.Text + "\\" + Path.GetFileNameWithoutExtension(txtBoxInput.Text) + ".dmp\"";
      }
      else {
        txtDump.Text = "";
        txtDump.Enabled = false;
      }
      btnCmdHelp.Enabled = true;
    }

    // helpボタン実行時
    private void btnCmdHelp_Click(object sender, EventArgs e) {
      string origCommand;
      origCommand = txtCommandLine.Text;
      txtCommandLine.Text = cmbCommand.SelectedItem + " -h";
      txtStdOutput.Text = "> volatility.exe " + txtCommandLine.Text + "\r\n";
      RunVolatilityStdout();
      txtCommandLine.Text = origCommand;
    }

    // -Dオプションのテキストボックス内容変更時
    private void textBoxDump_TextChanged(object sender, EventArgs e) {
      int i;
      string trimArg;
      i = txtCommandLine.Text.IndexOf("-D");
      if (i > 0) {
        trimArg = txtCommandLine.Text.Substring(0, i - 1);
        txtCommandLine.Text = trimArg + " -D \"" + txtOutput.Text + "\\" + txtDump.Text + "\"";
      }
    }
    
    // 実行(キャンセル)ボタンクリック時
    private void Run_Click(object sender, EventArgs e) {

      if (!File.Exists("volatility.exe")) {
        MessageBox.Show("volatilityプログラムが存在しません。\r\n\r\n"
          + "公式サイト(http://www.volatilityfoundation.org/)からスタンドアロン版の"
          + "Windowsプログラム(Volatility 2.4 Windows Standalone Executable)を入手してください。\r\n\r\n"
          + "入手したファイルのファイル名をvolatility.exeに変更してから"
          + "KaniVolatility.exeと同じフォルダに配置し、再度実行してください。",
          "実行エラー");
        Environment.Exit(0);
      }
      
      if (btnRun.Text == "実行") {
        btnRun.Text = "キャンセル";
        chkAutoSave.Enabled = false;
        chkStdOut.Enabled = false;

        // あらかじめ動いていたvolatilitlyプロセスのチェック
        Process[] ps = Process.GetProcessesByName("volatility");
        foreach (Process p in ps) {
          KnownId.Add(p.Id);
        }

        // 自動保存有効かつ出力フォルダに指定されたフォルダが存在しない場合は作成      
        if (chkAutoSave.Checked == true && Directory.Exists(txtOutput.Text) == false)
          Directory.CreateDirectory(txtOutput.Text);

        // 自動保存有効かつ-Dオプションで指定されたフォルダが存在しなければ作成
        if (cmbCommand.Text == "dlldump" || 
          cmbCommand.Text == "dumpfiles" || 
          cmbCommand.Text == "evtlogs" || 
          cmbCommand.Text == "memdump" || 
          cmbCommand.Text == "moddump" ||
          cmbCommand.Text == "procdump" || 
          cmbCommand.Text == "truecryptmaster" || 
          cmbCommand.Text == "screenshot" || 
          cmbCommand.Text == "vaddump" || 
          cmbCommand.Text == "verinfo" ||
          cmbCommand.Text == "dumpcerts" || 
          cmbCommand.Text == "linux_dump_map" || 
          cmbCommand.Text == "linux_moddump" || 
          cmbCommand.Text == "linux_librarydump" ||
          cmbCommand.Text == "linux_procdump" || 
          cmbCommand.Text == "linux_recover_filesystem" || 
          cmbCommand.Text == "linux_sk_buff_cache" || 
          cmbCommand.Text == "linux_pkt_queues" || 
          cmbCommand.Text == "mac_adium" ||
          cmbCommand.Text == "mac_librarydump" || 
          cmbCommand.Text == "mac_memdump" || 
          cmbCommand.Text == "mac_moddump" || 
          cmbCommand.Text == "mac_notesapp" ||
          cmbCommand.Text == "mac_procdump" || 
          cmbCommand.Text == "mac_recover_filesystem")
        {
        if (chkAutoSave.Checked == true && !Directory.Exists(txtOutput.Text + "\\" + txtDump.Text))
          Directory.CreateDirectory(txtOutput.Text + "\\" + txtDump.Text);
        }

        if (backgroundWorker1.IsBusy == false) {
          txtStdOutput.Text = "> volatility.exe " + txtCommandLine.Text + "\r\n";
          progressBar1.Style = ProgressBarStyle.Marquee;
          progressBar1.MarqueeAnimationSpeed = 30;
          backgroundWorker1.RunWorkerAsync();
        }
      }
      else {
        // 動作中のvolatilitlyプロセス情報を取得
        Process[] ps = Process.GetProcessesByName("volatility");
        // Kanivolatility経由で起動したと思われるプロセスのみを停止
        foreach (Process p in ps) {
          if(KnownId.Contains(p.Id) != true)
            p.Kill();
        }
        System.Threading.Thread.Sleep(1500);
        txtStdOutput.Text += "...停止完了\r\n";
        btnRun.Text = "実行";
        progressBar1.Style = ProgressBarStyle.Blocks;
        progressBar1.Value = 0;
      }
    }

    // バックグラウンドメイン処理用(DoWork)
    private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e) {

      try {
        process1.StartInfo.Arguments = txtCommandLine.Text;  // 引数
        process1.Start();
      }
      catch {
        MessageBox.Show("エラーが発生しました。KaniVolatilityを再起動してください。");
      }

      string commandOutputStd, commandErrStd;
      commandOutputStd = process1.StandardOutput.ReadToEnd();
      commandErrStd = process1.StandardError.ReadToEnd();
      process1.WaitForExit(60000); // 最大1分待機

      // 標準エラー出力、標準出力の順に表示
      e.Result = commandErrStd + "\r\n" + commandOutputStd;    
    }

    // バックグラウンド進捗バー制御用(何もしていない)
    private void backgroundWorker1_ProgressChanged(object sender, ProgressChangedEventArgs e) {
      progressBar1.Value = e.ProgressPercentage;
    }

    // バックグラウンドメイン処理終了時の後処理
    private void backgroundWorker1_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e) {
      progressBar1.Style = ProgressBarStyle.Blocks;
      progressBar1.Value = 0;
      btnRun.Text = "実行";

      if (chkStdOut.Checked)
        txtStdOutput.Text += e.Result;

      if (e.Result.ToString().Length == 0)
        txtStdOutput.Text += "結果はありませんでした。";

      txtStdOutput.SelectionStart = txtStdOutput.Text.Length;
      txtStdOutput.Focus();
      txtStdOutput.ScrollToCaret();

      // 自動保存有効時はコマンド名でファイルを保存
      if (chkAutoSave.Checked) {
        string outFile = txtOutput.Text + "\\" + cmbCommand.Text + ".txt";
        StreamWriter sw = new StreamWriter(outFile, false ,System.Text.Encoding.GetEncoding("shift_jis"));
        sw.Write(e.Result);
        sw.Close();
      }
      // オプションチェックを有効化状態に戻す
      chkAutoSave.Enabled = true;
      chkStdOut.Enabled = true;    

    }

    // Volatitliy.exe実行&ファイル保存(BATCH/KANI用)
    private void RunVolatilityFile(string command) {
      // コマンド名でファイルを保存
      string outFile = txtOutput.Text + "\\" + command + ".txt";
      StreamWriter sw = new StreamWriter(outFile, false, System.Text.Encoding.GetEncoding("shift_jis"));
      process1.Start();          
      sw.Write(process1.StandardOutput.ReadToEnd());
      sw.Close();

      process1.StandardError.ReadLine();
      string lineString;
      lineString = process1.StandardError.ReadLine();
      // 1行目はスキップしてその他にエラーがあれば保存
      if(lineString != null) {
        string outErrFile = txtOutput.Text + "\\error\\" + command + ".txt";
        StreamWriter swErr = new StreamWriter(outErrFile, false, System.Text.Encoding.GetEncoding("shift_jis"));
        swErr.WriteLine(lineString);
        while ((lineString = process1.StandardError.ReadLine()) != null)
          swErr.WriteLine(lineString);
        swErr.Close();
      }
      process1.WaitForExit(60000); // 最大1分待機
    }

    // Volatitliy.exe実行&標準出力(help/info用)
    private void RunVolatilityStdout() {
      process1.StartInfo.Arguments = txtCommandLine.Text; // 引数
      process1.Start();

      if (txtCommandLine.Text.Contains(" --info")) {
        string lineString, profileName;
        int i;
        cmbProfile.Items.Clear();
        cmbProfile.Items.AddRange(new object[] {
            "Win8SP1x64", 
            "Win8SP1x86", 
            "Win8SP0x64", 
            "Win8SP0x86", 
            "Win2012R2x64", 
            "Win2012x64", 
            "Win7SP1x64", 
            "Win7SP1x86", 
            "Win7SP0x64", 
            "Win7SP0x86", 
            "Win2008R2SP1x64", 
            "Win2008R2SP0x64", 
            "Win2008SP2x64",
            "Win2008SP2x86", 
            "Win2008SP1x64", 
            "Win2008SP1x86", 
            "VistaSP2x64", 
            "VistaSP2x86", 
            "VistaSP1x64",
            "VistaSP1x86", 
            "VistaSP0x64", 
            "VistaSP0x86", 
            "Win2003SP2x64", 
            "Win2003SP2x86", 
            "Win2003SP1x64",
            "Win2003SP1x86", 
            "Win2003SP0x86", 
            "WinXPSP3x86", 
            "WinXPSP2x64", 
            "WinXPSP2x86", 
            "WinXPSP1x64", 
            "Linux/Mac"});

        while ((lineString = process1.StandardOutput.ReadLine()) != null) {
          if (lineString.Contains("Profile") && (lineString.Contains("Linux") || lineString.Contains("Mac"))) {
            txtStdOutput.Text += lineString + "\r\n";
            i = lineString.IndexOf(" ");
            if (i > 0) {
              profileName = lineString.Substring(0, i);
              cmbProfile.Items.AddRange(new object[] { profileName });
            }
          }
        }
      } 
      else {  
        txtStdOutput.Text += process1.StandardOutput.ReadToEnd() + "\r\n";
      }
      txtStdOutput.SelectionStart = txtStdOutput.Text.Length;
      txtStdOutput.Focus();
      txtStdOutput.ScrollToCaret();
      process1.WaitForExit(60000); // 最大1分待機
    }

    // BATCH/KANIボタン実行時
    private void crabButton_Click(object sender, EventArgs e) {

      String[] array = new String[3];
      array[0] = cmbProfile.SelectedItem.ToString();
      array[1] = txtBoxInput.Text;
      array[2] = txtOutput.Text;

      if (btnCRAB.Text == "BATCH" || btnCRAB.Text == "KANI") {
        // 保存先フォルダに指定されたフォルダが存在しない場合は作成      
        if (!Directory.Exists(txtOutput.Text))
          Directory.CreateDirectory(txtOutput.Text);

        if (!Directory.Exists(txtOutput.Text + "\\error"))
          Directory.CreateDirectory(txtOutput.Text + "\\error");

        chkAutoSave.Enabled = false;
        chkStdOut.Enabled = false;
        btnRun.Enabled = false;
        txtStdOutput.Text = "";
        progressBar1.Style = ProgressBarStyle.Marquee;
        progressBar1.MarqueeAnimationSpeed = 30;
        backgroundWorker2.RunWorkerAsync(array);
      }
      else {
        btnCRAB.Enabled = false;
        txtStdOutput.Text += "停止処理中...";
        backgroundWorker2.CancelAsync();
      }
      btnCRAB.Text = "キャンセル";
    }

    // KANI/BATCH実行後バックグラウンド処理
    private void backgroundWorker2_DoWork(object sender, DoWorkEventArgs e) {

      // 進捗バー用カウンタ
      int numOfProc, maxNum;
      String[] strArg = (String[])e.Argument;

      numOfProc = 0;
      if (strArg[0].Contains("Linux")) {
        string[] commands = {
          "linux_pslist", 
          "linux_psaux", 
          "linux_pstree", 
          "linux_pslist_cache", 
          "linux_pidhashtable", 
          "linux_psxview", 
          "linux_lsof", 
          "linux_psenv", 
          "linux_threads",
          "linux_memmap", 
          "linux_proc_maps", 
          "linux_bash", 
          "linux_bash_env", 
          "linux_bash_hash",
          "linux_elfs", 
          "linux_library_list", 
          "linux_proc_maps_rb", 
          "linux_lsmod", 
          "linux_tmpfs", 
          "linux_hidden_modules", 
          "linux_info_regs", 
          "linux_kernel_opened_files",
          "linux_arp", 
          "linux_ifconfig", 
          "linux_route_cache", 
          "linux_netstat", 
          "linux_list_raw",
          "linux_malfind", 
          "linux_apihooks", 
          "linux_check_afinfo", 
          "linux_check_inline_kernel", 
          "linux_check_tty", 
          "linux_keyboard_notifiers", 
          "linux_check_creds", 
          "linux_check_fop", 
          "linux_check_idt", 
          "linux_check_syscall", 
          "linux_check_modules", 
          "linux_ldrmodules", 
          "linux_netfilter", 
          "linux_plthook", 
          "linux_cpuinfo", 
          "linux_dmesg", 
          "linux_iomem", 
          "linux_slabinfo", 
          "linux_mount", 
          "linux_mount_cache", 
          "linux_dentry_cache", 
          "linux_vma_cache", 
          "linux_enumerate_files",
          "linux_truecrypt_passphrase"
        };
        // find_fileは別オプションが必要なため除外、linux_memmapはメモリ不足の現象がでるため除外
        string[] dump_commands = { 
//          "linux_dump_map", 出力サイズが非常に大きくなるため除外
          "linux_moddump", 
          "linux_librarydump",
          "linux_procdump", 
          "linux_recover_filesystem", 
          "linux_sk_buff_cache", 
          "linux_pkt_queues"
        };

        maxNum = commands.Length + dump_commands.Length;

        foreach (string command in commands) {
          // キャンセルされてないか定期的にチェック
          if (backgroundWorker2.CancellationPending) {
            e.Cancel = true;
            return;
          }
          process1.StartInfo.Arguments = "--plugins=profiles --profile=" + strArg[0] + " -f \"" + strArg[1] + "\" " + command;
          RunVolatilityFile(command);
          backgroundWorker2.ReportProgress((numOfProc * 100) / maxNum);
          ++numOfProc;
        }
        foreach (string command in dump_commands) {
          // キャンセルされてないか定期的にチェック
          if (backgroundWorker2.CancellationPending) {
            e.Cancel = true;
            return;
          }
          process1.StartInfo.Arguments = "--plugins=profiles --profile=" + strArg[0] + " -f \"" + strArg[1] + "\" " + command;
          process1.StartInfo.Arguments += " -D \"" + strArg[2] + "\\" + command + "\"";
          if (!Directory.Exists(txtOutput.Text + "\\" + command))
            Directory.CreateDirectory(txtOutput.Text + "\\" + command);
          RunVolatilityFile(command);
          backgroundWorker2.ReportProgress((numOfProc*100) / maxNum);
          ++numOfProc;
        }
      }
      else if (strArg[0].Contains("Mac")) {
        string[] commands = {            
          "mac_pslist", 
          "mac_tasks", 
          "mac_pstree", 
          "mac_lsof", 
          "mac_pgrp_hash_table",
          "mac_pid_hash_table", 
          "mac_psaux", 
          "mac_dead_procs", 
          "mac_psxview", 
          "mac_proc_maps", 
          "mac_bash", 
          "mac_bash_env", 
          "mac_bash_hash", 
          "mac_list_sessions", 
          "mac_list_zones", 
          "mac_lsmod", 
          "mac_mount", 
          "mac_dyld_maps", 
//          "mac_list_files", 時間がかかるため除外
          "mac_lsmod_iokit", 
          "mac_lsmod_kext_map", 
          "mac_arp", 
          "mac_ifconfig", 
          "mac_netstat", 
          "mac_route", 
          "mac_dead_sockets", 
          "mac_network_conns",
          "mac_socket_filters", 
          "mac_malfind", 
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
//          "mac_ldrmodules", 時間がかかるため除外
          "mac_dmesg", 
          "mac_find_aslr_shift", 
          "mac_machine_info", 
          "mac_version", 
          "mac_print_boot_cmdline",
          "mac_dead_vnodes", 
          "mac_calendar", 
          "mac_contacts", 
          "mac_keychaindump"
        };
        string[] dump_commands = { 
          "mac_adium", 
//          "mac_dump_maps",  時間がかかるため除外
          "mac_librarydump",  
          "mac_memdump",  
          "mac_moddump",  
          "mac_notesapp", 
          "mac_procdump",  
          "mac_recover_filesystem",
          "mac_notesapp"
        };
        maxNum = commands.Length + dump_commands.Length;

        foreach (string command in commands) {
          // キャンセルされてないか定期的にチェック
          if (backgroundWorker2.CancellationPending) {
            e.Cancel = true;
            return;
          }
          process1.StartInfo.Arguments = "--plugins=profiles --profile=" + strArg[0] + " -f \"" + strArg[1] + "\" " + command;
          RunVolatilityFile(command);
          backgroundWorker2.ReportProgress((numOfProc * 100) / maxNum);
          ++numOfProc;
        }
        foreach (string command in dump_commands) {
          // キャンセルされてないか定期的にチェック
          if (backgroundWorker2.CancellationPending)
          {
            e.Cancel = true;
            return;
          }
          process1.StartInfo.Arguments = "--plugins=profiles --profile=" + strArg[0] + " -f \"" + strArg[1] + "\" " + command;
          process1.StartInfo.Arguments += " -D \"" + strArg[2] + "\\" + command + "\"";
          if (!Directory.Exists(txtOutput.Text + "\\" + command))
            Directory.CreateDirectory(txtOutput.Text + "\\" + command);
          RunVolatilityFile(command);
          backgroundWorker2.ReportProgress((numOfProc * 100) / maxNum);
          ++numOfProc;
        }      
      }
      else if (strArg[0].Contains("KANI")) {
        string[] commands = { 
          "pslist", 
          "pstree", 
          "psscan", 
          "dlllist", 
          "handles", 
          "getsids", 
          "cmdscan", 
          "consoles", 
          "cmdline", 
          "joblinks",
          "iehistory",
          "modules", 
          "modscan", 
          "ssdt", 
          "filescan", 
          "mutantscan", 
          "thrdscan", 
          "unloadedmodules", 
          "bigpools",
          "multiscan", 
          "objtypescan", 
          "pooltracker",
          "auditpol", 
          "hivelist", 
          "printkey", 
          "userassist", 
          "shellbags", 
          "shimcache", 
          "connections", 
          "connscan", 
          "sockets", 
          "sockscan", 
          "netscan",
          "mftparser",
          "malfind", 
          "svcscan", 
          "ldrmodules", 
          "apihooks", 
          "idt", 
          "gdt", 
          "threads", 
          "driverirp", 
          "devicetree", 
          "psxview", 
          "sessions", 
          "eventhooks", 
          "messagehooks", 
          "notepad",
          "truecryptpassphrase", 
          "truecryptsummary"
        };

        string[] dump_commands = { 
          "dlldump", 
          "dumpfiles", 
          "evtlogs", 
          "memdump", 
          "moddump", 
          "procdump", 
          "truecryptmaster", 
          "screenshot", 
          "vaddump", 
          "verinfo", 
          "dumpcerts"
        };

        // patcherはパッチファイルが必要＆&試作段階と思われるため除外
        // stringsは別途読み込みファイルが必要なため除外
        maxNum = commands.Length + dump_commands.Length;

        foreach (string command in commands) {
          // キャンセルされてないか定期的にチェック
          if (backgroundWorker2.CancellationPending) {
            e.Cancel = true;
            return;
          }
          process1.StartInfo.Arguments = "--profile=" + strArg[0] + " -f \"" + strArg[1] + "\" " + command;
          RunVolatilityFile(command);
          backgroundWorker2.ReportProgress((numOfProc * 100) / maxNum);
          ++numOfProc;
        }

        foreach (string command in dump_commands) {
          // キャンセルされてないか定期的にチェック
          if (backgroundWorker2.CancellationPending) {
            e.Cancel = true;
            return;
          }
          process1.StartInfo.Arguments = "--profile=" + strArg[0] + " -f \"" + strArg[1] + "\" " + command;
          process1.StartInfo.Arguments += " -D \"" + strArg[2] + "\\" + command + "\"";
          if (!Directory.Exists(txtOutput.Text + "\\" + command))
            Directory.CreateDirectory(txtOutput.Text + "\\" + command);
          RunVolatilityFile(command);
          backgroundWorker2.ReportProgress((numOfProc * 100) / maxNum);
          ++numOfProc;
        }
      }
      else { // WindowsでBATCHボタンの場合は一通り実行

        string[] commands = { 
          "pslist", 
          "pstree", 
          "psscan", 
          "dlllist", 
          "handles", 
          "getsids", 
          "cmdscan", 
          "consoles", 
          "privs", 
          "envars", 
          "cmdline", 
          "joblinks",
          "memmap", 
          "vadinfo", 
          "vadwalk",
          "vadtree", 
          "iehistory",
          "modules", 
          "modscan", 
          "ssdt", 
          "driverscan", 
          "filescan", 
          "mutantscan", 
          "symlinkscan", 
          "thrdscan", 
          "unloadedmodules", 
          "bigpools",
          "multiscan", 
          "objtypescan", 
          "poolpeek", 
          "pooltracker",
          "auditpol", 
          "hivelist", 
          "printkey", 
          "hivedump", 
          "lsadump",
          "userassist", 
          "shellbags", 
          "shimcache", 
          "getservicesids",
          "connections", 
          "connscan", 
          "sockets", 
          "sockscan", 
          "netscan",
          "mbrparser", 
          "mftparser",
          "malfind", 
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
          "windows", 
          "wintree", 
          "gditimers",
          "bioskbd", 
          "patcher", 
          "timeliner", 
          "notepad",
          "truecryptpassphrase", 
          "truecryptsummary"
        };

        string[] dump_commands = { 
          "dlldump", 
          "dumpfiles", 
          "evtlogs", 
          "memdump", 
          "moddump", 
          "procdump", 
          "truecryptmaster", 
          "screenshot", 
          "vaddump", 
          "verinfo", 
          "dumpcerts"
        };

        maxNum = commands.Length + dump_commands.Length;

        foreach (string command in commands) {
          // キャンセルされてないか定期的にチェック
          if (backgroundWorker2.CancellationPending) {
            e.Cancel = true;
            return;
          }
          process1.StartInfo.Arguments = "--profile=" + strArg[0] + " -f \"" + strArg[1] + "\" " + command;
          RunVolatilityFile(command);
          backgroundWorker2.ReportProgress((numOfProc * 100) / maxNum);
          ++numOfProc;
        }

        foreach (string command in dump_commands) {
          // キャンセルされてないか定期的にチェック
          if (backgroundWorker2.CancellationPending) {
            e.Cancel = true;
            return;
          }
          process1.StartInfo.Arguments = "--profile=" + strArg[0] + " -f \"" + strArg[1] + "\" " + command;
          process1.StartInfo.Arguments += " -D \"" + strArg[2] + "\\" + command + "\"";
          if (!Directory.Exists(txtOutput.Text + "\\" + command))
            Directory.CreateDirectory(txtOutput.Text + "\\" + command);
          RunVolatilityFile(command);
          backgroundWorker2.ReportProgress((numOfProc * 100) / maxNum);
          ++numOfProc;
        }
      }
    }

    // 進捗表示
    private void backgroundWorker2_ProgressChanged(object sender, ProgressChangedEventArgs e) {
      txtStdOutput.Text += "> volatility.exe " 
        + process1.StartInfo.Arguments + " (" + e.ProgressPercentage +" %)\r\n";
      txtStdOutput.SelectionStart = txtStdOutput.Text.Length;
      txtStdOutput.Focus();
      txtStdOutput.ScrollToCaret();
    }

    // BATCH/KANI実行終了時
    private void backgroundWorker2_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e) {
      chkAutoSave.Enabled = true;
      chkStdOut.Enabled = true;
      btnRun.Enabled = true;
      btnCRAB.Visible = false;
      txtStdOutput.Text += "完了\r\n";
      progressBar1.Style = ProgressBarStyle.Blocks;
      progressBar1.Value = 0;
      if (e.Cancelled)
        MessageBox.Show(this,"キャンセルしました");
      else
        MessageBox.Show(this,"終了しました");

      txtStdOutput.SelectionStart = txtStdOutput.Text.Length;
      txtStdOutput.Focus();
      txtStdOutput.ScrollToCaret();
    }

    private void Form1_Load(object sender, EventArgs e) {
    }

    private void lblcom_MouseDoubleClick(object sender, MouseEventArgs e) {
      if (btnCRAB.Visible == false) {
        btnCRAB.Visible = true;
        btnCRAB.Text = "BATCH";
      }
      else if (btnCRAB.Text == "キャンセル")
        return;
      else if (btnCRAB.Text == "BATCH")
        btnCRAB.Text = "KANI";
      else
        btnCRAB.Visible = false;
    }

  }
}

