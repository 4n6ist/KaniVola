using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace KaniVola
{
    public partial class about : Form
    {
        public about()
        {
            InitializeComponent();
            string appProductName = Application.ProductName;
            string appVersion = Application.ProductVersion;
            lblAbout.Text = appProductName + " " + appVersion;     
        }
    }
}
