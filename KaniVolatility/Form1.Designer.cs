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
			this.txtBoxInput = new System.Windows.Forms.TextBox();
			this.btnInputFile = new System.Windows.Forms.Button();
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
			this.lblRun = new System.Windows.Forms.Label();
			this.txtCommandLine = new System.Windows.Forms.TextBox();
			this.lblProgName = new System.Windows.Forms.Label();
			this.backgroundWorker1 = new System.ComponentModel.BackgroundWorker();
			this.process1 = new System.Diagnostics.Process();
			this.progressBar1 = new System.Windows.Forms.ProgressBar();
			this.saveFileDialog = new System.Windows.Forms.SaveFileDialog();
			this.lblDump = new System.Windows.Forms.Label();
			this.txtDump = new System.Windows.Forms.TextBox();
			this.btnCRAB = new System.Windows.Forms.Button();
			this.btnCmdHelp = new System.Windows.Forms.Button();
			this.backgroundWorker2 = new System.ComponentModel.BackgroundWorker();
			this.lblDOption = new System.Windows.Forms.Label();
			this.chkStdOut = new System.Windows.Forms.CheckBox();
			this.label1 = new System.Windows.Forms.Label();
			this.SuspendLayout();
			// 
			// lblOutput
			// 
			this.lblOutput.AutoSize = true;
			this.lblOutput.Location = new System.Drawing.Point(10, 104);
			this.lblOutput.Name = "lblOutput";
			this.lblOutput.Size = new System.Drawing.Size(64, 12);
			this.lblOutput.TabIndex = 0;
			this.lblOutput.Text = "出力フォルダ";
			// 
			// lblInput
			// 
			this.lblInput.AutoSize = true;
			this.lblInput.Location = new System.Drawing.Point(11, 13);
			this.lblInput.Name = "lblInput";
			this.lblInput.Size = new System.Drawing.Size(63, 12);
			this.lblInput.TabIndex = 1;
			this.lblInput.Text = "対象ファイル";
			// 
			// txtBoxInput
			// 
			this.txtBoxInput.AllowDrop = true;
			this.txtBoxInput.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
			this.txtBoxInput.Location = new System.Drawing.Point(79, 10);
			this.txtBoxInput.Name = "txtBoxInput";
			this.txtBoxInput.ReadOnly = true;
			this.txtBoxInput.RightToLeft = System.Windows.Forms.RightToLeft.No;
			this.txtBoxInput.Size = new System.Drawing.Size(626, 19);
			this.txtBoxInput.TabIndex = 2;
			this.txtBoxInput.DragDrop += new System.Windows.Forms.DragEventHandler(this.textBoxInput_DragDrop);
			this.txtBoxInput.DragEnter += new System.Windows.Forms.DragEventHandler(this.textBox_DragEnter);
			// 
			// btnInputFile
			// 
			this.btnInputFile.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
			this.btnInputFile.Location = new System.Drawing.Point(711, 10);
			this.btnInputFile.Name = "btnInputFile";
			this.btnInputFile.Size = new System.Drawing.Size(61, 19);
			this.btnInputFile.TabIndex = 3;
			this.btnInputFile.Text = "選択";
			this.btnInputFile.UseVisualStyleBackColor = true;
			this.btnInputFile.Click += new System.EventHandler(this.buttonInputFile_Click);
			// 
			// txtOutput
			// 
			this.txtOutput.AllowDrop = true;
			this.txtOutput.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
			this.txtOutput.Location = new System.Drawing.Point(79, 101);
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
			this.btnOutput.Location = new System.Drawing.Point(711, 101);
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
			this.btnRun.Location = new System.Drawing.Point(711, 175);
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
			this.txtStdOutput.Location = new System.Drawing.Point(12, 200);
			this.txtStdOutput.MaxLength = 1073741824;
			this.txtStdOutput.Multiline = true;
			this.txtStdOutput.Name = "txtStdOutput";
			this.txtStdOutput.ScrollBars = System.Windows.Forms.ScrollBars.Both;
			this.txtStdOutput.Size = new System.Drawing.Size(760, 327);
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
			this.cmbProfile.Items.AddRange(new object[] {
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
			this.cmbProfile.Location = new System.Drawing.Point(80, 40);
			this.cmbProfile.Name = "cmbProfile";
			this.cmbProfile.Size = new System.Drawing.Size(200, 20);
			this.cmbProfile.TabIndex = 11;
			this.cmbProfile.SelectedIndexChanged += new System.EventHandler(this.cmbProfile_SelectedIndexChanged);
			// 
			// lblProfile
			// 
			this.lblProfile.AutoSize = true;
			this.lblProfile.Location = new System.Drawing.Point(17, 43);
			this.lblProfile.Name = "lblProfile";
			this.lblProfile.Size = new System.Drawing.Size(57, 12);
			this.lblProfile.TabIndex = 12;
			this.lblProfile.Text = "プロファイル";
			// 
			// lblCategory
			// 
			this.lblCategory.AutoSize = true;
			this.lblCategory.Location = new System.Drawing.Point(352, 43);
			this.lblCategory.Name = "lblCategory";
			this.lblCategory.Size = new System.Drawing.Size(39, 12);
			this.lblCategory.TabIndex = 13;
			this.lblCategory.Text = "カテゴリ";
			// 
			// cmbCategory
			// 
			this.cmbCategory.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
			this.cmbCategory.FormattingEnabled = true;
			this.cmbCategory.Items.AddRange(new object[] {
            "イメージスキャン/変換"});
			this.cmbCategory.Location = new System.Drawing.Point(397, 40);
			this.cmbCategory.Name = "cmbCategory";
			this.cmbCategory.Size = new System.Drawing.Size(150, 20);
			this.cmbCategory.TabIndex = 14;
			this.cmbCategory.SelectedIndexChanged += new System.EventHandler(this.comboBox2_SelectedIndexChanged);
			// 
			// lblCommand
			// 
			this.lblCommand.AutoSize = true;
			this.lblCommand.Location = new System.Drawing.Point(34, 74);
			this.lblCommand.Name = "lblCommand";
			this.lblCommand.Size = new System.Drawing.Size(40, 12);
			this.lblCommand.TabIndex = 15;
			this.lblCommand.Text = "コマンド";
			// 
			// cmbCommand
			// 
			this.cmbCommand.FormattingEnabled = true;
			this.cmbCommand.Location = new System.Drawing.Point(79, 71);
			this.cmbCommand.Name = "cmbCommand";
			this.cmbCommand.Size = new System.Drawing.Size(200, 20);
			this.cmbCommand.TabIndex = 16;
			this.cmbCommand.SelectedIndexChanged += new System.EventHandler(this.comboBox3_SelectedIndexChanged);
			this.cmbCommand.TextUpdate += new System.EventHandler(this.comboBox3_SelectedIndexChanged);
			// 
			// chkAutoSave
			// 
			this.chkAutoSave.AutoSize = true;
			this.chkAutoSave.Checked = true;
			this.chkAutoSave.CheckState = System.Windows.Forms.CheckState.Checked;
			this.chkAutoSave.Location = new System.Drawing.Point(79, 131);
			this.chkAutoSave.Name = "chkAutoSave";
			this.chkAutoSave.Size = new System.Drawing.Size(617, 16);
			this.chkAutoSave.TabIndex = 19;
			this.chkAutoSave.Text = "実行結果を出力フォルダ配下に「コマンド名.txt」の形式で自動保存 (注意：同名のファイルが既に存在する場合、上書きします)";
			this.chkAutoSave.UseVisualStyleBackColor = true;
			// 
			// lblRun
			// 
			this.lblRun.AutoSize = true;
			this.lblRun.Location = new System.Drawing.Point(10, 178);
			this.lblRun.Name = "lblRun";
			this.lblRun.Size = new System.Drawing.Size(64, 12);
			this.lblRun.TabIndex = 20;
			this.lblRun.Text = "実行コマンド";
			this.lblRun.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(this.lblcom_MouseDoubleClick);
			// 
			// txtCommandLine
			// 
			this.txtCommandLine.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
			this.txtCommandLine.Location = new System.Drawing.Point(146, 175);
			this.txtCommandLine.Name = "txtCommandLine";
			this.txtCommandLine.Size = new System.Drawing.Size(560, 19);
			this.txtCommandLine.TabIndex = 21;
			// 
			// lblProgName
			// 
			this.lblProgName.AutoSize = true;
			this.lblProgName.Location = new System.Drawing.Point(77, 178);
			this.lblProgName.Name = "lblProgName";
			this.lblProgName.Size = new System.Drawing.Size(69, 12);
			this.lblProgName.TabIndex = 22;
			this.lblProgName.Text = "volatility.exe";
			// 
			// backgroundWorker1
			// 
			this.backgroundWorker1.WorkerReportsProgress = true;
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
			this.progressBar1.Location = new System.Drawing.Point(12, 533);
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
			// lblDump
			// 
			this.lblDump.AutoSize = true;
			this.lblDump.Location = new System.Drawing.Point(372, 74);
			this.lblDump.Name = "lblDump";
			this.lblDump.Size = new System.Drawing.Size(19, 12);
			this.lblDump.TabIndex = 25;
			this.lblDump.Text = "-D";
			// 
			// txtDump
			// 
			this.txtDump.Location = new System.Drawing.Point(397, 71);
			this.txtDump.Name = "txtDump";
			this.txtDump.Size = new System.Drawing.Size(150, 19);
			this.txtDump.TabIndex = 26;
			this.txtDump.TextChanged += new System.EventHandler(this.textBoxDump_TextChanged);
			// 
			// btnCRAB
			// 
			this.btnCRAB.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
			this.btnCRAB.Location = new System.Drawing.Point(712, 174);
			this.btnCRAB.Name = "btnCRAB";
			this.btnCRAB.Size = new System.Drawing.Size(61, 19);
			this.btnCRAB.TabIndex = 27;
			this.btnCRAB.Text = "BATCH";
			this.btnCRAB.UseVisualStyleBackColor = true;
			this.btnCRAB.Visible = false;
			this.btnCRAB.Click += new System.EventHandler(this.crabButton_Click);
			// 
			// btnCmdHelp
			// 
			this.btnCmdHelp.Location = new System.Drawing.Point(285, 70);
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
			// lblDOption
			// 
			this.lblDOption.AutoSize = true;
			this.lblDOption.Location = new System.Drawing.Point(553, 74);
			this.lblDOption.Name = "lblDOption";
			this.lblDOption.Size = new System.Drawing.Size(153, 12);
			this.lblDOption.TabIndex = 31;
			this.lblDOption.Text = "(出力フォルダ配下のフォルダ名)";
			// 
			// chkStdOut
			// 
			this.chkStdOut.AutoSize = true;
			this.chkStdOut.Checked = true;
			this.chkStdOut.CheckState = System.Windows.Forms.CheckState.Checked;
			this.chkStdOut.Location = new System.Drawing.Point(79, 153);
			this.chkStdOut.Name = "chkStdOut";
			this.chkStdOut.Size = new System.Drawing.Size(335, 16);
			this.chkStdOut.TabIndex = 32;
			this.chkStdOut.Text = "実行結果を表示 (注意：出力内容が多い場合、速度低下します)";
			this.chkStdOut.UseVisualStyleBackColor = true;
			// 
			// label1
			// 
			this.label1.AutoSize = true;
			this.label1.Location = new System.Drawing.Point(26, 144);
			this.label1.Name = "label1";
			this.label1.Size = new System.Drawing.Size(48, 12);
			this.label1.TabIndex = 33;
			this.label1.Text = "オプション";
			// 
			// Form1
			// 
			this.AcceptButton = this.btnRun;
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.ClientSize = new System.Drawing.Size(784, 562);
			this.Controls.Add(this.label1);
			this.Controls.Add(this.chkStdOut);
			this.Controls.Add(this.lblDOption);
			this.Controls.Add(this.btnCmdHelp);
			this.Controls.Add(this.btnCRAB);
			this.Controls.Add(this.txtDump);
			this.Controls.Add(this.lblDump);
			this.Controls.Add(this.progressBar1);
			this.Controls.Add(this.lblProgName);
			this.Controls.Add(this.txtCommandLine);
			this.Controls.Add(this.lblRun);
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
			this.Controls.Add(this.btnInputFile);
			this.Controls.Add(this.txtBoxInput);
			this.Controls.Add(this.lblInput);
			this.Controls.Add(this.lblOutput);
			this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
			this.Name = "Form1";
			this.Text = "KaniVolatility v0.8 - Ji2 Forensics Lab (http://www.ji2.co.jp/forensics/)";
			this.Load += new System.EventHandler(this.Form1_Load);
			this.ResumeLayout(false);
			this.PerformLayout();

    }

    #endregion

    private System.Windows.Forms.Label lblOutput;
    private System.Windows.Forms.Label lblInput;
    private System.Windows.Forms.TextBox txtBoxInput;
    private System.Windows.Forms.Button btnInputFile;
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
    private System.Windows.Forms.Label lblRun;
    private System.Windows.Forms.TextBox txtCommandLine;
    private System.Windows.Forms.Label lblProgName;
    private System.ComponentModel.BackgroundWorker backgroundWorker1;
    private System.Diagnostics.Process process1;
    private System.Windows.Forms.ProgressBar progressBar1;
    private System.Windows.Forms.SaveFileDialog saveFileDialog;
    private System.Windows.Forms.TextBox txtDump;
    private System.Windows.Forms.Label lblDump;
    private System.Windows.Forms.Button btnCRAB;
    private System.Windows.Forms.Button btnCmdHelp;
    private System.ComponentModel.BackgroundWorker backgroundWorker2;
    private System.Windows.Forms.Label lblDOption;
    private System.Windows.Forms.CheckBox chkStdOut;
    private System.Windows.Forms.Label label1;
  }
}

