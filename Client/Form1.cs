using AESImplementation;
using RSAImplementation;
using SimpleTcp;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Client
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        SimpleTcpClient client;
        KeyPair kp;
        int counter = 0;
        BigInteger cPk; 

        Key serverPk;
        
        AESEncrypt aEnc;
        AESDecrypt aDec;
        RSADecrypt rd = new RSADecrypt();
        RSAEncrypt re = new RSAEncrypt();
        
        private void btnConnect_Click(object sender, EventArgs e)
        {
            try
            {
                client.Connect();
                btnSend.Enabled = true;
                btnConnect.Enabled = false;
            }
            catch(Exception ex)
            {
                MessageBox.Show(ex.Message,"Message", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void label1_Click(object sender, EventArgs e)
        {
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            client = new SimpleTcpClient(txtIp.Text);
            client.Events.Connected += Events_Connected;
            client.Events.DataReceived += Events_DataRecieved;
            client.Events.Disconnected += Events_Disconnected;
            btnSend.Enabled = false;
            
            aEnc = new AESEncrypt();
            aDec =  new AESDecrypt();
            KeyGenerate kg = new KeyGenerate();
            kp = kg.GenerateKey(1024);
        }

        private void Events_Disconnected(object sender, ConnectionEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                txtInfo.Text += $"Server disconnected. {Environment.NewLine}";
            });
        }

        private void Events_DataRecieved(object sender, DataReceivedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                if (counter == 0)
                {
                    txtInfo.Text += $"-----Public Key of Server------ {Environment.NewLine}";
                    txtInfo.Text += $"Server: {ASCIIEncoding.UTF8.GetString(e.Data)} {Environment.NewLine}";
                    txtInfo.Text += $"-------------------{Environment.NewLine} End of public key{Environment.NewLine}";
                    cPk = new BigInteger(e.Data);
                    serverPk = new Key(cPk);
                } else 
                {   
                    byte[] aesEKey = e.Data.Slice(0, 128);
                    byte[] aesKey = rd.DecryptBytes(aesEKey, kp.privateKey);
                    byte[] recievedETxt = e.Data.Slice(128, e.Data.Length);
                    byte[] recievedTxt = aDec.DecryptByte(recievedETxt, aesEKey);
                    txtInfo.Text += $"Server: {ASCIIEncoding.UTF8.GetString(recievedTxt)} {Environment.NewLine}";
                }
                counter++;
            });
        }

        private void Events_Connected(object sender, ConnectionEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                txtInfo.Text += $"Server Connected. {Environment.NewLine}";
                client.Send(kp.publicKey.n.ToByteArray());
            });
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            if (client.IsConnected)
            {
                if (!string.IsNullOrEmpty(txtMessage.Text))
                {
                    byte[] symKey = AESImplementation.Utility.GenerateRandomByte(16);
                    byte[] encryptedKey = re.EncryptBytes(symKey, serverPk);
                    byte[] encryptedTxt = aEnc.EncryptByte(ASCIIEncoding.UTF8.GetBytes(txtMessage.Text), encryptedKey);
                    byte[] toSend = encryptedKey.Concat(encryptedTxt).ToArray();
                    client.Send(toSend);
                    txtInfo.Text += $"Me: {txtMessage.Text} {Environment.NewLine}";
                    txtMessage.Text = string.Empty;
                }
            }
        }
    }
}
