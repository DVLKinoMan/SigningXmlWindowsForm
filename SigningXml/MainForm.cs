using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;
using System.Xml;

namespace SigningXml
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
            textBox4.Text = "Aa123456";
            //textBox3.Text = @"D:\Projects\NBE-Dev\AltaSoft.Nbe.Processor\bin\Debug\cert.pfx";
            textBox3.Text = @"C:\Users\d.dvali\Desktop\Aa123456 tsttbcnbe.tbcbank.ge.pfx";
            textBox5.Text = @"C:\Users\d.dvali\Desktop\certnew.p7b";
        }

        private void Button1_Click(object sender, EventArgs e)
        {
            try
            {
                var doc = new XmlDocument();
                doc.LoadXml(textBox1.Text);
                var tuple = NbeXmlDocumentSigner.SignBodyParameter(textBox1.Text, NbeXmlDocumentSigner.GetPrivateKeyFromPath(textBox3.Text, textBox4.Text));

                textBox2.Text = tuple.signedEnvelope;
            }
            catch(Exception exc)
            {
                MessageBox.Show(exc.Message);
            }
        }

        private void OpenFileDialog1_FileOk(object sender, CancelEventArgs e)
        {

        }

        private void Button2_Click(object sender, EventArgs e)
        {
            if(openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                textBox3.Text = openFileDialog1.FileName;
            }
        }

        private void Button3_Click(object sender, EventArgs e)
        {
            try
            {
                var doc = new XmlDocument();
                doc.LoadXml(textBox2.Text);

                var xmlElement = doc.GetElementsByTagName("xml")[0];
                var decodedSignature = HttpUtility.HtmlDecode(xmlElement.InnerText);

                //string path = @"D:\Projects\NBE-Dev\AltaSoft.Nbe.Processor\bin\Debug\publickey.cer";
                //string path = @"C:\Users\d.dvali\Desktop\certnew.p7b";
                //string path = textBox5.Text;

                var doc2 = new XmlDocument();
                doc2.LoadXml(decodedSignature);

                if (!checkBox1.Checked)
                {
                    if (NbeXmlDocumentSigner.ValidateSignature(doc2,
                        NbeXmlDocumentSigner.GetPublicKeyFromPath(textBox5.Text)))
                        MessageBox.Show("CheckedSignature Successful");
                    else
                        MessageBox.Show("CheckedSignature not Successful");
                }
                else
                {
                    if (NbeXmlDocumentSigner.ValidateSignature(doc2,
                        NbeXmlDocumentSigner.GetPrivateKeyFromPath(textBox3.Text, textBox4.Text))
                    ) //()))//.GetPrivateKeyFromPath(@"C:\Users\d.dvali\Desktop\Aa123456 tsttbcnbe.tbcbank.ge.pfx", "1")))//(@"C:\Users\d.dvali\Desktop\certnew.p7b")))
                        MessageBox.Show("CheckedSignature Successful");
                    else
                        MessageBox.Show("CheckedSignature not Successful");
                }
            }

            catch(Exception exc)
            {
                MessageBox.Show(exc.Message);
            }
        }

        private void Button4_Click(object sender, EventArgs e)
        {
            if (openFileDialog2.ShowDialog() == DialogResult.OK)
            {
                textBox5.Text = openFileDialog2.FileName;
            }
        }
    }
}
