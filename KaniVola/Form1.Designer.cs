namespace KaniVolatility
{
  partial class Form1
  {
    /// <summary>
    /// 必要なデザイナー変数です。
    /// </summary>
    private System.ComponentModel.IContainer components = null;

    /// <summary>
    /// 使用中のリソースをすべてクリーンアップします。
    /// </summary>
    /// <param name="disposing">マネージ リソースが破棄される場合 true、破棄されない場合は false です。</param>
    protected override void Dispose(bool disposing)
    {
      if (disposing && (components != null))
      {
        components.Dispose();
      }
      base.Dispose(disposing);
    }

    #region Windows フォーム デザイナーで生成されたコード

    /// <summary>
    /// デザイナー サポートに必要なメソッドです。このメソッドの内容を
    /// コード エディターで変更しないでください。
    /// </summary>
    private void InitializeComponent()
    {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.lblOutput = new System.Windows.Forms.Label();
            this.lblInput = new System.Windows.Forms.Label();
            this.txtInput = new System.Windows.Forms.TextBox();
            this.btnInput = new System.Windows.Forms.Button();
            this.txtOutput = new System.Windows.Forms.TextBox();
            this.btnOutput = new System.Windows.Forms.Button();
            this.btnRun = new System.Windows.Forms.Button();
            this.txtStdOutput = new System.Windows.Forms.TextBox();
            this.openFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.folderBrowserDialogOutput = new System.Windows.Forms.FolderBrowserDialog();
            this.cmbProfile = new System.Windows.Forms.ComboBox();
            this.lblProfile = new System.Windows.Forms.Label();
            this.lblCategory = new System.Windows.Forms.Label();
            this.cmbCategory = new System.Windows.Forms.ComboBox();
            this.lblCommand = new System.Windows.Forms.Label();
            this.cmbCommand = new System.Windows.Forms.ComboBox();
            this.chkAutoSave = new System.Windows.Forms.CheckBox();
            this.txtCommandLine = new System.Windows.Forms.TextBox();
            this.lblProgName = new System.Windows.Forms.Label();
            this.backgroundWorker1 = new System.ComponentModel.BackgroundWorker();
            this.process1 = new System.Diagnostics.Process();
            this.progressBar1 = new System.Windows.Forms.ProgressBar();
            this.saveFileDialog = new System.Windows.Forms.SaveFileDialog();
            this.btnCmdHelp = new System.Windows.Forms.Button();
            this.backgroundWorker2 = new System.ComponentModel.BackgroundWorker();
            this.chkStdOut = new System.Windows.Forms.CheckBox();
            this.label1 = new System.Windows.Forms.Label();
            this.chkJST = new System.Windows.Forms.CheckBox();
            this.chkPlugins = new System.Windows.Forms.CheckBox();
            this.process2 = new System.Diagnostics.Process();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.fileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.対象ファイルToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aff4ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.helpToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.menuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // lblOutput
            // 
            this.lblOutput.AutoSize = true;
            this.lblOutput.Location = new System.Drawing.Point(10, 55);
            this.lblOutput.Name = "lblOutput";
            this.lblOutput.Size = new System.Drawing.Size(64, 12);
            this.lblOutput.TabIndex = 0;
            this.lblOutput.Text = "出力フォルダ";
            // 
            // lblInput
            // 
            this.lblInput.AutoSize = true;
            this.lblInput.Location = new System.Drawing.Point(13, 30);
            this.lblInput.Name = "lblInput";
            this.lblInput.Size = new System.Drawing.Size(63, 12);
            this.lblInput.TabIndex = 1;
            this.lblInput.Text = "対象ファイル";
            // 
            // txtInput
            // 
            this.txtInput.AllowDrop = true;
            this.txtInput.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtInput.Location = new System.Drawing.Point(79, 27);
            this.txtInput.Name = "txtInput";
            this.txtInput.ReadOnly = true;
            this.txtInput.RightToLeft = System.Windows.Forms.RightToLeft.No;
            this.txtInput.Size = new System.Drawing.Size(626, 19);
            this.txtInput.TabIndex = 2;
            this.txtInput.DragDrop += new System.Windows.Forms.DragEventHandler(this.textBoxInput_DragDrop);
            this.txtInput.DragEnter += new System.Windows.Forms.DragEventHandler(this.textBox_DragEnter);
            // 
            // btnInput
            // 
            this.btnInput.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnInput.Location = new System.Drawing.Point(711, 27);
            this.btnInput.Name = "btnInput";
            this.btnInput.Size = new System.Drawing.Size(61, 19);
            this.btnInput.TabIndex = 3;
            this.btnInput.Text = "選択";
            this.btnInput.UseVisualStyleBackColor = true;
            this.btnInput.Click += new System.EventHandler(this.buttonInputFile_Click);
            // 
            // txtOutput
            // 
            this.txtOutput.AllowDrop = true;
            this.txtOutput.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtOutput.Location = new System.Drawing.Point(79, 52);
            this.txtOutput.Name = "txtOutput";
            this.txtOutput.ReadOnly = true;
            this.txtOutput.RightToLeft = System.Windows.Forms.RightToLeft.No;
            this.txtOutput.Size = new System.Drawing.Size(626, 19);
            this.txtOutput.TabIndex = 4;
            this.txtOutput.DragDrop += new System.Windows.Forms.DragEventHandler(this.textBoxOutput_DragDrop);
            this.txtOutput.DragEnter += new System.Windows.Forms.DragEventHandler(this.textBox_DragEnter);
            // 
            // btnOutput
            // 
            this.btnOutput.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnOutput.Location = new System.Drawing.Point(711, 52);
            this.btnOutput.Name = "btnOutput";
            this.btnOutput.Size = new System.Drawing.Size(61, 19);
            this.btnOutput.TabIndex = 5;
            this.btnOutput.Text = "選択";
            this.btnOutput.UseVisualStyleBackColor = true;
            this.btnOutput.Click += new System.EventHandler(this.buttonOutput_Click);
            // 
            // btnRun
            // 
            this.btnRun.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnRun.Location = new System.Drawing.Point(711, 171);
            this.btnRun.Name = "btnRun";
            this.btnRun.Size = new System.Drawing.Size(61, 19);
            this.btnRun.TabIndex = 9;
            this.btnRun.Text = "実行";
            this.btnRun.UseVisualStyleBackColor = true;
            this.btnRun.Click += new System.EventHandler(this.Run_Click);
            // 
            // txtStdOutput
            // 
            this.txtStdOutput.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtStdOutput.Font = new System.Drawing.Font("ＭＳ ゴシック", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.txtStdOutput.Location = new System.Drawing.Point(12, 210);
            this.txtStdOutput.MaxLength = 1073741824;
            this.txtStdOutput.Multiline = true;
            this.txtStdOutput.Name = "txtStdOutput";
            this.txtStdOutput.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.txtStdOutput.Size = new System.Drawing.Size(760, 316);
            this.txtStdOutput.TabIndex = 10;
            this.txtStdOutput.WordWrap = false;
            // 
            // openFileDialog
            // 
            this.openFileDialog.ReadOnlyChecked = true;
            this.openFileDialog.RestoreDirectory = true;
            // 
            // cmbProfile
            // 
            this.cmbProfile.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbProfile.FormattingEnabled = true;
            this.cmbProfile.Location = new System.Drawing.Point(79, 80);
            this.cmbProfile.Name = "cmbProfile";
            this.cmbProfile.Size = new System.Drawing.Size(198, 20);
            this.cmbProfile.TabIndex = 11;
            this.cmbProfile.SelectedIndexChanged += new System.EventHandler(this.cmbProfile_SelectedIndexChanged);
            // 
            // lblProfile
            // 
            this.lblProfile.AutoSize = true;
            this.lblProfile.Location = new System.Drawing.Point(17, 83);
            this.lblProfile.Name = "lblProfile";
            this.lblProfile.Size = new System.Drawing.Size(57, 12);
            this.lblProfile.TabIndex = 12;
            this.lblProfile.Text = "プロファイル";
            // 
            // lblCategory
            // 
            this.lblCategory.AutoSize = true;
            this.lblCategory.Location = new System.Drawing.Point(33, 111);
            this.lblCategory.Name = "lblCategory";
            this.lblCategory.Size = new System.Drawing.Size(39, 12);
            this.lblCategory.TabIndex = 13;
            this.lblCategory.Text = "カテゴリ";
            // 
            // cmbCategory
            // 
            this.cmbCategory.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbCategory.FormattingEnabled = true;
            this.cmbCategory.Location = new System.Drawing.Point(79, 108);
            this.cmbCategory.Name = "cmbCategory";
            this.cmbCategory.Size = new System.Drawing.Size(198, 20);
            this.cmbCategory.TabIndex = 14;
            this.cmbCategory.SelectedIndexChanged += new System.EventHandler(this.comboBox2_SelectedIndexChanged);
            // 
            // lblCommand
            // 
            this.lblCommand.AutoSize = true;
            this.lblCommand.Location = new System.Drawing.Point(33, 142);
            this.lblCommand.Name = "lblCommand";
            this.lblCommand.Size = new System.Drawing.Size(40, 12);
            this.lblCommand.TabIndex = 15;
            this.lblCommand.Text = "コマンド";
            // 
            // cmbCommand
            // 
            this.cmbCommand.FormattingEnabled = true;
            this.cmbCommand.Location = new System.Drawing.Point(79, 135);
            this.cmbCommand.Name = "cmbCommand";
            this.cmbCommand.Size = new System.Drawing.Size(150, 20);
            this.cmbCommand.TabIndex = 16;
            this.cmbCommand.SelectedIndexChanged += new System.EventHandler(this.comboBox3_SelectedIndexChanged);
            this.cmbCommand.TextUpdate += new System.EventHandler(this.comboBox3_SelectedIndexChanged);
            // 
            // chkAutoSave
            // 
            this.chkAutoSave.AutoSize = true;
            this.chkAutoSave.Checked = true;
            this.chkAutoSave.CheckState = System.Windows.Forms.CheckState.Checked;
            this.chkAutoSave.Location = new System.Drawing.Point(352, 84);
            this.chkAutoSave.Name = "chkAutoSave";
            this.chkAutoSave.Size = new System.Drawing.Size(353, 16);
            this.chkAutoSave.TabIndex = 19;
            this.chkAutoSave.Text = "実行結果を出力フォルダ配下に保存 (ファイルが存在する場合上書き)";
            this.chkAutoSave.UseVisualStyleBackColor = true;
            // 
            // txtCommandLine
            // 
            this.txtCommandLine.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtCommandLine.Location = new System.Drawing.Point(78, 171);
            this.txtCommandLine.Multiline = true;
            this.txtCommandLine.Name = "txtCommandLine";
            this.txtCommandLine.Size = new System.Drawing.Size(626, 33);
            this.txtCommandLine.TabIndex = 21;
            this.txtCommandLine.Text = " --tz=Asia/Tokyo ";
            // 
            // lblProgName
            // 
            this.lblProgName.AutoSize = true;
            this.lblProgName.Location = new System.Drawing.Point(3, 174);
            this.lblProgName.Name = "lblProgName";
            this.lblProgName.Size = new System.Drawing.Size(69, 12);
            this.lblProgName.TabIndex = 22;
            this.lblProgName.Text = "volatility.exe";
            // 
            // backgroundWorker1
            // 
            this.backgroundWorker1.WorkerReportsProgress = true;
            this.backgroundWorker1.WorkerSupportsCancellation = true;
            this.backgroundWorker1.DoWork += new System.ComponentModel.DoWorkEventHandler(this.backgroundWorker1_DoWork);
            this.backgroundWorker1.ProgressChanged += new System.ComponentModel.ProgressChangedEventHandler(this.backgroundWorker1_ProgressChanged);
            this.backgroundWorker1.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.backgroundWorker1_RunWorkerCompleted);
            // 
            // process1
            // 
            this.process1.StartInfo.CreateNoWindow = true;
            this.process1.StartInfo.Domain = "";
            this.process1.StartInfo.ErrorDialog = true;
            this.process1.StartInfo.FileName = "volatility.exe";
            this.process1.StartInfo.LoadUserProfile = false;
            this.process1.StartInfo.Password = null;
            this.process1.StartInfo.RedirectStandardError = true;
            this.process1.StartInfo.RedirectStandardOutput = true;
            this.process1.StartInfo.StandardErrorEncoding = null;
            this.process1.StartInfo.StandardOutputEncoding = null;
            this.process1.StartInfo.UserName = "";
            this.process1.StartInfo.UseShellExecute = false;
            this.process1.SynchronizingObject = this;
            // 
            // progressBar1
            // 
            this.progressBar1.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.progressBar1.Location = new System.Drawing.Point(12, 532);
            this.progressBar1.Name = "progressBar1";
            this.progressBar1.Size = new System.Drawing.Size(760, 23);
            this.progressBar1.TabIndex = 23;
            // 
            // saveFileDialog
            // 
            this.saveFileDialog.DefaultExt = "txt";
            this.saveFileDialog.FileName = "output.txt";
            this.saveFileDialog.Filter = "*.txt|*.*";
            // 
            // btnCmdHelp
            // 
            this.btnCmdHelp.Location = new System.Drawing.Point(237, 135);
            this.btnCmdHelp.Name = "btnCmdHelp";
            this.btnCmdHelp.Size = new System.Drawing.Size(40, 20);
            this.btnCmdHelp.TabIndex = 30;
            this.btnCmdHelp.Text = "help";
            this.btnCmdHelp.UseVisualStyleBackColor = true;
            this.btnCmdHelp.Click += new System.EventHandler(this.btnCmdHelp_Click);
            // 
            // backgroundWorker2
            // 
            this.backgroundWorker2.WorkerReportsProgress = true;
            this.backgroundWorker2.WorkerSupportsCancellation = true;
            this.backgroundWorker2.DoWork += new System.ComponentModel.DoWorkEventHandler(this.backgroundWorker2_DoWork);
            this.backgroundWorker2.ProgressChanged += new System.ComponentModel.ProgressChangedEventHandler(this.backgroundWorker2_ProgressChanged);
            this.backgroundWorker2.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.backgroundWorker2_RunWorkerCompleted);
            // 
            // chkStdOut
            // 
            this.chkStdOut.AutoSize = true;
            this.chkStdOut.Checked = true;
            this.chkStdOut.CheckState = System.Windows.Forms.CheckState.Checked;
            this.chkStdOut.Location = new System.Drawing.Point(352, 106);
            this.chkStdOut.Name = "chkStdOut";
            this.chkStdOut.Size = new System.Drawing.Size(105, 16);
            this.chkStdOut.TabIndex = 32;
            this.chkStdOut.Text = "実行結果を表示";
            this.chkStdOut.UseVisualStyleBackColor = true;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(298, 85);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(48, 12);
            this.label1.TabIndex = 33;
            this.label1.Text = "オプション";
            // 
            // chkJST
            // 
            this.chkJST.AutoSize = true;
            this.chkJST.Checked = true;
            this.chkJST.CheckState = System.Windows.Forms.CheckState.Checked;
            this.chkJST.Location = new System.Drawing.Point(352, 129);
            this.chkJST.Name = "chkJST";
            this.chkJST.Size = new System.Drawing.Size(303, 16);
            this.chkJST.TabIndex = 37;
            this.chkJST.Text = "タイムゾーンをJST(UTC+0900)に設定 (--tz=Asia/Tokyo)";
            this.chkJST.UseVisualStyleBackColor = true;
            this.chkJST.Click += new System.EventHandler(this.chkJST_Click);
            // 
            // chkPlugins
            // 
            this.chkPlugins.AutoSize = true;
            this.chkPlugins.Location = new System.Drawing.Point(352, 152);
            this.chkPlugins.Name = "chkPlugins";
            this.chkPlugins.Size = new System.Drawing.Size(242, 16);
            this.chkPlugins.TabIndex = 38;
            this.chkPlugins.Text = "pluginsフォルダを有効化 (--plugins=plugins)";
            this.chkPlugins.UseVisualStyleBackColor = true;
            this.chkPlugins.Click += new System.EventHandler(this.chkPlugins_Click);
            // 
            // process2
            // 
            this.process2.StartInfo.Domain = "";
            this.process2.StartInfo.ErrorDialog = true;
            this.process2.StartInfo.FileName = "winpmem.exe";
            this.process2.StartInfo.LoadUserProfile = false;
            this.process2.StartInfo.Password = null;
            this.process2.StartInfo.StandardErrorEncoding = null;
            this.process2.StartInfo.StandardOutputEncoding = null;
            this.process2.StartInfo.UserName = "";
            this.process2.StartInfo.UseShellExecute = false;
            this.process2.SynchronizingObject = this;
            // 
            // menuStrip1
            // 
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fileToolStripMenuItem,
            this.toolToolStripMenuItem,
            this.helpToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(784, 24);
            this.menuStrip1.TabIndex = 39;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // fileToolStripMenuItem
            // 
            this.fileToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.対象ファイルToolStripMenuItem});
            this.fileToolStripMenuItem.Name = "fileToolStripMenuItem";
            this.fileToolStripMenuItem.Size = new System.Drawing.Size(53, 20);
            this.fileToolStripMenuItem.Text = "ファイル";
            // 
            // 対象ファイルToolStripMenuItem
            // 
            this.対象ファイルToolStripMenuItem.Name = "対象ファイルToolStripMenuItem";
            this.対象ファイルToolStripMenuItem.Size = new System.Drawing.Size(132, 22);
            this.対象ファイルToolStripMenuItem.Text = "対象ファイル";
            this.対象ファイルToolStripMenuItem.Click += new System.EventHandler(this.buttonInputFile_Click);
            // 
            // toolToolStripMenuItem
            // 
            this.toolToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.aff4ToolStripMenuItem});
            this.toolToolStripMenuItem.Name = "toolToolStripMenuItem";
            this.toolToolStripMenuItem.Size = new System.Drawing.Size(46, 20);
            this.toolToolStripMenuItem.Text = "ツール";
            // 
            // aff4ToolStripMenuItem
            // 
            this.aff4ToolStripMenuItem.Name = "aff4ToolStripMenuItem";
            this.aff4ToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.aff4ToolStripMenuItem.Text = "AFF4";
            this.aff4ToolStripMenuItem.Click += new System.EventHandler(this.aff4ToolStripMenuItem_Click);
            // 
            // helpToolStripMenuItem
            // 
            this.helpToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.aboutToolStripMenuItem});
            this.helpToolStripMenuItem.Name = "helpToolStripMenuItem";
            this.helpToolStripMenuItem.Size = new System.Drawing.Size(48, 20);
            this.helpToolStripMenuItem.Text = "ヘルプ";
            // 
            // aboutToolStripMenuItem
            // 
            this.aboutToolStripMenuItem.Name = "aboutToolStripMenuItem";
            this.aboutToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.aboutToolStripMenuItem.Text = "バージョン情報";
            this.aboutToolStripMenuItem.Click += new System.EventHandler(this.aboutToolStripMenuItem_Click);
            // 
            // Form1
            // 
            this.AcceptButton = this.btnRun;
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(784, 561);
            this.Controls.Add(this.chkPlugins);
            this.Controls.Add(this.chkJST);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.chkStdOut);
            this.Controls.Add(this.btnCmdHelp);
            this.Controls.Add(this.progressBar1);
            this.Controls.Add(this.lblProgName);
            this.Controls.Add(this.txtCommandLine);
            this.Controls.Add(this.chkAutoSave);
            this.Controls.Add(this.cmbCommand);
            this.Controls.Add(this.lblCommand);
            this.Controls.Add(this.cmbCategory);
            this.Controls.Add(this.lblCategory);
            this.Controls.Add(this.lblProfile);
            this.Controls.Add(this.cmbProfile);
            this.Controls.Add(this.txtStdOutput);
            this.Controls.Add(this.btnRun);
            this.Controls.Add(this.btnOutput);
            this.Controls.Add(this.txtOutput);
            this.Controls.Add(this.btnInput);
            this.Controls.Add(this.txtInput);
            this.Controls.Add(this.lblInput);
            this.Controls.Add(this.lblOutput);
            this.Controls.Add(this.menuStrip1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.menuStrip1;
            this.Name = "Form1";
            this.Text = "KaniVola (GUI for Volatility)";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

    }

    #endregion

    private System.Windows.Forms.Label lblOutput;
    private System.Windows.Forms.Label lblInput;
    private System.Windows.Forms.TextBox txtInput;
    private System.Windows.Forms.Button btnInput;
    private System.Windows.Forms.TextBox txtOutput;
    private System.Windows.Forms.Button btnOutput;
    private System.Windows.Forms.Button btnRun;
    private System.Windows.Forms.TextBox txtStdOutput;
    private System.Windows.Forms.FolderBrowserDialog folderBrowserDialogOutput;
    private System.Windows.Forms.ComboBox cmbProfile;
    private System.Windows.Forms.Label lblProfile;
    private System.Windows.Forms.OpenFileDialog openFileDialog;
    private System.Windows.Forms.Label lblCategory;
    private System.Windows.Forms.ComboBox cmbCategory;
    private System.Windows.Forms.Label lblCommand;
    private System.Windows.Forms.ComboBox cmbCommand;
    private System.Windows.Forms.CheckBox chkAutoSave;
    private System.Windows.Forms.TextBox txtCommandLine;
    private System.Windows.Forms.Label lblProgName;
    private System.ComponentModel.BackgroundWorker backgroundWorker1;
    private System.Diagnostics.Process process1;
    private System.Windows.Forms.ProgressBar progressBar1;
    private System.Windows.Forms.SaveFileDialog saveFileDialog;
    private System.Windows.Forms.Button btnCmdHelp;
    private System.ComponentModel.BackgroundWorker backgroundWorker2;
    private System.Windows.Forms.CheckBox chkStdOut;
    private System.Windows.Forms.Label label1;
        private System.Windows.Forms.CheckBox chkJST;
        private System.Windows.Forms.CheckBox chkPlugins;
        private System.Diagnostics.Process process2;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem toolToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem helpToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aff4ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aboutToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem 対象ファイルToolStripMenuItem;
    }
}

