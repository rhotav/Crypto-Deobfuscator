using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Crypto_Deobfuscator
{
    public partial class MainPage : Form
    {
        #region Variables
        string directoryName = "";
        string filePath = "";
        static ModuleDefMD module = null;
        static System.Reflection.Assembly assembly;
        public Thread thr;
        public static int junkMethod = 0;
        public static string stringMethod = "";
        public static string stringType = "";
        public static string int32Type = "";
        public static string floatType = "";
        public static int decStrings = 0;
        public static int decFloats = 0;
        public static int decInts = 0;
        public static MethodDef stringInitializeMethod = null;
        public static int stringMethodCount = 0;
        public static string int32Methods = "";
        public static int int32MethodCount = 0;
        public static string floatMethods = "";
        public static int floatMethodCount = 0;
        #endregion

        #region Form Design
        [System.Runtime.InteropServices.DllImport("Gdi32.dll", EntryPoint = "CreateRoundRectRgn")]
        private static extern IntPtr CreateRoundRectRgn
       (
           int nLeftRect,     // x-coordinate of upper-left corner
           int nTopRect,      // y-coordinate of upper-left corner
           int nRightRect,    // x-coordinate of lower-right corner
           int nBottomRect,   // y-coordinate of lower-right corner
           int nWidthEllipse, // width of ellipse
           int nHeightEllipse // height of ellipse
       );

        public const int WM_NCLBUTTONDOWN = 0xA1;
        public const int HT_CAPTION = 0x2;

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern bool ReleaseCapture();
        
        public MainPage()
        {
            CheckForIllegalCrossThreadCalls = false;
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Region = System.Drawing.Region.FromHrgn(CreateRoundRectRgn(0, 0, Width, Height, 20, 20));
            if (!IsUserAdministrator())
            {
                MessageBox.Show("Please application to run as administrator", "Crypto Deobfuscator", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(0);
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            Environment.Exit(0);
        }

        private void panel2_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                ReleaseCapture();
                SendMessage(Handle, WM_NCLBUTTONDOWN, HT_CAPTION, 0);
            }
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            if (label3.Left > -300)
            {
                label3.Left -= 2;
            }
            else
            {
                label3.Left = 600;
            }
        }
        #endregion

        #region dragDrop and Select
        private void listBox1_DragDrop(object sender, DragEventArgs e)
        {
            try
            {
                Array array = (Array)e.Data.GetData(DataFormats.FileDrop);
                if (array != null)
                {
                    string text = array.GetValue(0).ToString();
                    int num = text.LastIndexOf(".");
                    if (num != -1)
                    {
                        string text2 = text.Substring(num);
                        text2 = text2.ToLower();
                        if (text2 == ".exe" || text2 == ".dll")
                        {
                            Activate();
                            int num2 = text.LastIndexOf("\\");
                            if (num2 != -1)
                            {
                                directoryName = text.Remove(num2, text.Length - num2);
                            }
                            if (directoryName.Length == 2)
                            {
                                directoryName += "\\";
                            }
                            module = ModuleDefMD.Load(text);
                            filePath = text;
                            label1.Text = "Loaded !";
                            label1.ForeColor = Color.White;
                            label2.Visible = false;
                            listBox1.Items.Clear();
                            listBox1.Items.Add("EntryPoint MDToken : 0x" + module.EntryPoint.MDToken.ToString());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                filePath = "";
                module = null;
                MessageBox.Show(ex.Message, "Error !", MessageBoxButtons.OK, MessageBoxIcon.Error);
                label1.Text = "Not Loaded !";
                label1.ForeColor = Color.LightGray;

            }
        }

        private void listBox1_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
            }
            else
            {
                e.Effect = DragDropEffects.None;
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            try
            {
                OpenFileDialog open = new OpenFileDialog();
                open.Filter = "Executable Files|*.exe|DLL Files |*.dll";
                if (open.ShowDialog() == DialogResult.OK)
                {
                    module = ModuleDefMD.Load(open.FileName);
                    filePath = open.FileName;
                    label1.Text = "Loaded !";
                    label1.ForeColor = Color.LightGray;
                    listBox1.Items.Clear();
                    label2.Visible = false;
                    listBox1.Items.Add("EntryPoint MDToken : 0x" + module.EntryPoint.MDToken.ToString());
                }
            }
            catch (Exception ex)
            {
                filePath = "";
                module = null;
                MessageBox.Show(ex.Message, "Error !", MessageBoxButtons.OK, MessageBoxIcon.Error);
                label1.Text = "Not Loaded !";
                label1.ForeColor = Color.White;
                label2.Visible = true;

            }
        }
        #endregion

        private void button3_Click(object sender, EventArgs e)
        {
            if (filePath != string.Empty && module != null)
            {
                thr = new Thread(new ThreadStart(CodeBlock));
                thr.Start();
                button3.Enabled = false;
                button4.Enabled = false;
                listBox1.AllowDrop = false;
            }
        }


        private void CodeBlock()
        {
            JunkCleaner();
            entryCleaner();
            Renamer();
            FuncIdentifier();
            StringDecoder();
            int32Decoder();
            floatDecoder();
            cctorCleaner();


            SaveAssembly("_deobf");
            listBox1.Items.Add("Compeleted and Saved !");

            try
            {
                if (File.Exists(Path.GetDirectoryName(module.Location) + @"\" + Path.GetFileNameWithoutExtension(module.Location) + "_temp" + ".exe"))
                {
                    File.Delete(Path.GetDirectoryName(module.Location) + @"\" + Path.GetFileNameWithoutExtension(module.Location) + "_temp" + ".exe");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error while deleting..\n" + ex.Message, "Crypto Deobfuscator",MessageBoxButtons.OK,MessageBoxIcon.Error);
            }
        }

        public void entryCleaner()
        {
            CilBody cctor = module.EntryPoint.Body;

            for (int i = 0; i < cctor.Instructions.Count; i++)
            {
                if (cctor.Instructions[i].OpCode == OpCodes.Call &&
                    cctor.Instructions[i + 1].OpCode == OpCodes.Call)
                {
                    cctor.Instructions.RemoveAt(i);
                    cctor.Instructions.RemoveAt(i);
                    break;
                }
            }
            listBox1.Items.Add("Demo message is cleaned.");
            listBox1.Items.Add("Debugger Control is cleaned.");

        }
        public void Renamer()
        {
            int form = 1;
            int method = 0;
            int xclass = 1;
            int field = 0;

            foreach (TypeDef type in module.Types)
            {
                if (type.Name == "<Module>") continue;
                if (type.IsRuntimeSpecialName) continue;
                if (type.BaseType.ToString().Contains("Forms.Form"))
                {
                    type.Name = "Form_" + form.ToString();
                    form++;

                }
                else
                {
                    type.Name = "Class_" + xclass.ToString();
                    xclass++;
                }

                foreach (MethodDef methodDef in type.Methods)
                {
                    if (methodDef.IsConstructor && methodDef.IsRuntimeSpecialName) continue;

                    methodDef.Name = "Method_" + method.ToString();
                    method++;
                }

                foreach (FieldDef fieldDef in type.Fields)
                {
                    if (fieldDef.IsRuntimeSpecialName) continue;

                    fieldDef.Name = "Field_" + field.ToString();
                    field++;
                }

            }
            int result = form + xclass + field + method;
            listBox1.Items.Add(result.ToString() + " names changed.");

        }
        public void JunkCleaner()
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody) continue;

                    for (int i = 0; i < method.Body.Instructions.Count; i++)
                    {
                        if ((method.Body.Instructions[i].IsLdcI4() &&
                            method.Body.Instructions[i + 1].OpCode == OpCodes.Switch &&
                            method.Body.Instructions[i + 2].OpCode == OpCodes.Ldc_I4_1 &&
                            method.Body.Instructions[i + 3].OpCode == OpCodes.Brtrue_S &&
                            method.Body.Instructions[i + 4].OpCode == OpCodes.Ldtoken))
                        {
                            method.Body.Instructions.RemoveAt(i);
                            method.Body.Instructions.RemoveAt(i);
                            method.Body.Instructions.RemoveAt(i);
                            method.Body.Instructions.RemoveAt(i);
                            method.Body.Instructions.RemoveAt(i);
                            method.Body.Instructions.RemoveAt(i);
                            junkMethod++;

                        }
                        else if (method.Body.Instructions[i].IsLdcI4() &&
                            method.Body.Instructions[i + 1].OpCode == OpCodes.Switch &&
                            method.Body.Instructions[i + 2].OpCode != OpCodes.Ldc_I4_1)
                        {
                            method.Body.Instructions.RemoveAt(i);
                            method.Body.Instructions.RemoveAt(i);
                            junkMethod++;

                        }


                    }

                }
            }
            listBox1.Items.Add(junkMethod + " junks cleaned");

        }
        public void FuncIdentifier()
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody) continue;

                    string identify = MethodTypeIdentifier(method, type);

                    if (identify == "stringMethod")
                    {
                        stringMethod = method.Name;
                        stringMethodCount++;
                        stringInitializeMethod = method;
                        stringType = type.Name;
                        continue;
                    }
                    else if (identify == "int32Method")
                    {
                        int32Methods = method.Name;
                        int32Type = type.Name;
                        int32MethodCount++;
                        continue;
                    }
                    else if (identify == "floatMethod")
                    {
                        floatMethods = method.Name;
                        floatType = type.Name;
                        floatMethodCount++;
                        continue;
                    }
                }
            }
            listBox1.Items.Add("Identified string method");
            listBox1.Items.Add("Identified int32 method");
            listBox1.Items.Add("Identified float method");
        }
        public string MethodTypeIdentifier(MethodDef method, TypeDef type)
        {
            for (int i = 0; i < method.Body.Instructions.Count; i++)
            {
                if (method.Body.Instructions[i].IsLdcI4() &&
                    method.Body.Instructions[i + 1].IsStloc() &&
                    method.Body.Instructions[i + 2].OpCode == OpCodes.Ldsfld &&
                    method.Body.Instructions[i + 3].IsLdarg() &&
                    method.Body.Instructions[i + 4].OpCode == OpCodes.Ldelem_U1 &&
                    method.Body.Instructions[i + 5].IsLdcI4() &&
                    method.Body.Instructions[method.Body.Instructions.Count - 1].OpCode == OpCodes.Ret &&
                    method.Body.Instructions[method.Body.Instructions.Count - 2].OpCode == OpCodes.Pop)
                {
                    return "stringMethod";
                }

                if (method.Body.Instructions[i].OpCode == OpCodes.Ldsfld &&
                    method.Body.Instructions[i + 1].IsLdarg() &&
                    method.Body.Instructions[i + 2].OpCode == OpCodes.Call &&
                    method.Body.Instructions[i + 2].Operand.ToString().Contains("ToInt32") &&
                    method.Body.Instructions[i + 3].OpCode == OpCodes.Dup)
                {
                    return "int32Method";
                }

                if (method.Body.Instructions[i].OpCode == OpCodes.Ldsfld &&
                    method.Body.Instructions[i + 1].IsLdarg() &&
                    method.Body.Instructions[i + 2].OpCode == OpCodes.Call &&
                    method.Body.Instructions[i + 2].Operand.ToString().Contains("ToSingle") &&
                    method.Body.Instructions[i + 3].OpCode == OpCodes.Dup)
                {
                    return "floatMethod";
                }
            }

            return "nothing";
        }
        public void StringDecoder()
        {
            SaveAssembly("_temp");
            File.SetAttributes(Path.GetDirectoryName(module.Location) + @"\" + Path.GetFileNameWithoutExtension(module.Location) + "_temp" + ".exe", System.IO.FileAttributes.Hidden);

            assembly = System.Reflection.Assembly.LoadFrom(Path.GetDirectoryName(module.Location) + @"\" + Path.GetFileNameWithoutExtension(module.Location) + "_temp" + ".exe");
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody) continue;

                    for (int i =0; i < method.Body.Instructions.Count; i++)
                    {
                        if (method.Body.Instructions[i].OpCode == OpCodes.Call &&
                            method.Body.Instructions[i].Operand.ToString().Contains(stringMethod))
                        {
                            System.Reflection.BindingFlags eFlags = System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic;
                            Type classInstance = null;
                            foreach (Type type1 in assembly.GetTypes()) {
                                if (type1.Name == stringType)
                                {
                                    classInstance = type1;
                                    break;
                                }
                                
                            }

                            System.Reflection.MethodInfo myMethod = classInstance.GetMethod(stringMethod, eFlags);
                            object[] arguments = { method.Body.Instructions[i - 1].Operand };
                            string result = (string)myMethod.Invoke(null, arguments);
                            method.Body.Instructions.RemoveAt(i);
                            method.Body.Instructions[i - 1].OpCode = OpCodes.Ldstr;
                            method.Body.Instructions[i - 1].Operand = result;
                            decStrings++;
                        }


                    }

                }
            }

            listBox1.Items.Add(decStrings + " strings decrypted.");
        

        }
        public void int32Decoder()
        {
            try
            {
                foreach (TypeDef type in module.Types)
                {
                    foreach (MethodDef method in type.Methods)
                    {
                        if (!method.HasBody) continue;

                        for (int i = 0; i < method.Body.Instructions.Count; i++)
                        {
                            if (method.Body.Instructions[i].OpCode == OpCodes.Call &&
                                method.Body.Instructions[i].Operand.ToString().Contains(int32Methods))
                            {
                                System.Reflection.BindingFlags eFlags = System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic;
                                Type classInstance = null;
                                foreach (Type type1 in assembly.GetTypes())
                                {
                                    if (type1.Name == int32Type)
                                    {
                                        classInstance = type1;
                                        break;
                                    }

                                }

                                System.Reflection.MethodInfo myMethod = classInstance.GetMethod(int32Methods, eFlags);
                                object[] arguments = { method.Body.Instructions[i - 1].GetLdcI4Value() };
                                int result = (int)myMethod.Invoke(null, arguments);
                                method.Body.Instructions.RemoveAt(i);
                                method.Body.Instructions[i - 1].OpCode = OpCodes.Ldc_I4;
                                method.Body.Instructions[i - 1].Operand = result;
                                decInts++;
                            }


                        }

                    }
                }
            }
            catch (Exception ex)
            {

            }
            listBox1.Items.Add(decInts + " integers decrypted.");
        }
        public void floatDecoder()
        {
            try
            {
                foreach (TypeDef type in module.Types)
                {
                    foreach (MethodDef method in type.Methods)
                    {
                        if (!method.HasBody) continue;

                        for (int i = 0; i < method.Body.Instructions.Count; i++)
                        {
                            if (method.Body.Instructions[i].OpCode == OpCodes.Call &&
                                method.Body.Instructions[i].Operand.ToString().Contains(floatMethods))
                            {
                                System.Reflection.BindingFlags eFlags = System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic;
                                Type classInstance = null;
                                foreach (Type type1 in assembly.GetTypes())
                                {
                                    if (type1.Name == floatType)
                                    {
                                        classInstance = type1;
                                        break;
                                    }

                                }

                                System.Reflection.MethodInfo myMethod = classInstance.GetMethod(floatMethods, eFlags);
                                object[] arguments = { method.Body.Instructions[i - 1].GetLdcI4Value() };
                                float result = (float)myMethod.Invoke(null, arguments);
                                method.Body.Instructions.RemoveAt(i);
                                method.Body.Instructions[i - 1].OpCode = OpCodes.Ldc_I4_S;
                                method.Body.Instructions[i - 1].Operand = result;
                            }


                        }

                    }
                }
            }
            catch (Exception Ex)
            {
                decFloats++;
            }
            listBox1.Items.Add(decInts + " floats decrypted.");
        }
        public void cctorCleaner()
        {
            MethodDef cctor = module.GlobalType.FindOrCreateStaticConstructor();

            for (int i = 0; i < cctor.Body.Instructions.Count; i++)
            {
                if (cctor.Body.Instructions[i].OpCode == OpCodes.Call)
                {
                    cctor.Body.Instructions[i].OpCode = OpCodes.Nop;
                }
            }

            if (module.Resources.Count == 1)
            {
                module.Resources.Clear();
            }
            else
            {
                string text = assembly.FullName;
                int num = text.IndexOf(',');
                text = text.Substring(0, num);
                Resource asd = module.Resources.Find(text + '&');
                module.Resources.Remove(asd);
                
            }

            listBox1.Items.Add("Resources and CCTOR cleaned.");


        }



        #region Save

        public bool IsUserAdministrator()
        {
            bool isAdmin;
            try
            {
                WindowsIdentity user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (UnauthorizedAccessException ex)
            {
                isAdmin = false;
            }
            catch (Exception ex)
            {
                isAdmin = false;
            }
            return isAdmin;
        }

        public void SaveAssembly(string ext)
        {
            var writerOptions = new NativeModuleWriterOptions(module, true);
            writerOptions.Logger = DummyLogger.NoThrowInstance;
            writerOptions.MetadataOptions.Flags = (MetadataFlags.PreserveTypeRefRids | MetadataFlags.PreserveTypeDefRids | MetadataFlags.PreserveFieldRids | MetadataFlags.PreserveMethodRids | MetadataFlags.PreserveParamRids | MetadataFlags.PreserveMemberRefRids | MetadataFlags.PreserveStandAloneSigRids | MetadataFlags.PreserveEventRids | MetadataFlags.PreservePropertyRids | MetadataFlags.PreserveTypeSpecRids | MetadataFlags.PreserveMethodSpecRids | MetadataFlags.PreserveStringsOffsets | MetadataFlags.PreserveUSOffsets | MetadataFlags.PreserveBlobOffsets | MetadataFlags.PreserveAll | MetadataFlags.AlwaysCreateGuidHeap | MetadataFlags.PreserveExtraSignatureData | MetadataFlags.KeepOldMaxStack);
            module.NativeWrite(Path.GetDirectoryName(module.Location) + @"\" + Path.GetFileNameWithoutExtension(module.Location) + ext + ".exe", writerOptions);

        }

        #endregion

    }
}
