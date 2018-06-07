namespace KaniVola
{
    partial class license
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(license));
            this.lblLicenseESET = new System.Windows.Forms.Label();
            this.licenseESET = new System.Windows.Forms.TextBox();
            this.licenseJPCERT = new System.Windows.Forms.TextBox();
            this.lblJPCERT = new System.Windows.Forms.Label();
            this.lblLicenseCommunity = new System.Windows.Forms.Label();
            this.lblLicenseCommunityURL = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // lblLicenseESET
            // 
            this.lblLicenseESET.AutoSize = true;
            this.lblLicenseESET.Font = new System.Drawing.Font("MS UI Gothic", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.lblLicenseESET.Location = new System.Drawing.Point(12, 226);
            this.lblLicenseESET.Name = "lblLicenseESET";
            this.lblLicenseESET.Size = new System.Drawing.Size(81, 12);
            this.lblLicenseESET.TabIndex = 4;
            this.lblLicenseESET.Text = "broserhooks:";
            // 
            // licenseESET
            // 
            this.licenseESET.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.licenseESET.Location = new System.Drawing.Point(12, 241);
            this.licenseESET.Multiline = true;
            this.licenseESET.Name = "licenseESET";
            this.licenseESET.ReadOnly = true;
            this.licenseESET.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.licenseESET.Size = new System.Drawing.Size(420, 100);
            this.licenseESET.TabIndex = 0;
            this.licenseESET.TabStop = false;
            this.licenseESET.Text = resources.GetString("licenseESET.Text");
            // 
            // licenseJPCERT
            // 
            this.licenseJPCERT.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.licenseJPCERT.Location = new System.Drawing.Point(12, 91);
            this.licenseJPCERT.Multiline = true;
            this.licenseJPCERT.Name = "licenseJPCERT";
            this.licenseJPCERT.ReadOnly = true;
            this.licenseJPCERT.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.licenseJPCERT.Size = new System.Drawing.Size(420, 100);
            this.licenseJPCERT.TabIndex = 0;
            this.licenseJPCERT.TabStop = false;
            this.licenseJPCERT.Text = resources.GetString("licenseJPCERT.Text");
            // 
            // lblJPCERT
            // 
            this.lblJPCERT.AutoSize = true;
            this.lblJPCERT.Font = new System.Drawing.Font("MS UI Gothic", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.lblJPCERT.Location = new System.Drawing.Point(12, 64);
            this.lblJPCERT.Name = "lblJPCERT";
            this.lblJPCERT.Size = new System.Drawing.Size(310, 24);
            this.lblJPCERT.TabIndex = 2;
            this.lblJPCERT.Text = "agtidconfig, apt17scan, derusbiconfig, hikitconfig, \r\nredleavesconfig, redleavess" +
    "can:";
            // 
            // lblLicenseCommunity
            // 
            this.lblLicenseCommunity.AutoSize = true;
            this.lblLicenseCommunity.Font = new System.Drawing.Font("MS UI Gothic", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(128)));
            this.lblLicenseCommunity.Location = new System.Drawing.Point(12, 13);
            this.lblLicenseCommunity.Name = "lblLicenseCommunity";
            this.lblLicenseCommunity.Size = new System.Drawing.Size(177, 12);
            this.lblLicenseCommunity.TabIndex = 0;
            this.lblLicenseCommunity.Text = "Volatility Community Plugin:\r\n";
            this.lblLicenseCommunity.Click += new System.EventHandler(this.label1_Click);
            // 
            // lblLicenseCommunityURL
            // 
            this.lblLicenseCommunityURL.AutoSize = true;
            this.lblLicenseCommunityURL.Location = new System.Drawing.Point(12, 25);
            this.lblLicenseCommunityURL.Name = "lblLicenseCommunityURL";
            this.lblLicenseCommunityURL.Size = new System.Drawing.Size(263, 12);
            this.lblLicenseCommunityURL.TabIndex = 1;
            this.lblLicenseCommunityURL.Text = "https://github.com/volatilityfoundation/community";
            // 
            // license
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(444, 381);
            this.Controls.Add(this.lblLicenseCommunityURL);
            this.Controls.Add(this.lblLicenseCommunity);
            this.Controls.Add(this.licenseJPCERT);
            this.Controls.Add(this.lblJPCERT);
            this.Controls.Add(this.licenseESET);
            this.Controls.Add(this.lblLicenseESET);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "license";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "ライセンス";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label lblLicenseESET;
        private System.Windows.Forms.TextBox licenseESET;
        private System.Windows.Forms.TextBox licenseJPCERT;
        private System.Windows.Forms.Label lblJPCERT;
        private System.Windows.Forms.Label lblLicenseCommunity;
        private System.Windows.Forms.Label lblLicenseCommunityURL;
    }
}