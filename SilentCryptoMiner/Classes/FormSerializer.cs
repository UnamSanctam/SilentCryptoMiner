using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
using System.Xml;

namespace FormSerialization
{
    public static class FormSerializer
    {

        /* Form Serializer by Unam Sanctam https://github.com/UnamSanctam, based on http://www.codeproject.com/KB/dialog/SavingTheStateOfAForm.aspx */

        public static void Serialise(List<Control> cntrls, string XmlFileName)
        {
            XmlTextWriter xmlSerialisedForm = new XmlTextWriter(XmlFileName, System.Text.Encoding.Default);
            xmlSerialisedForm.Formatting = Formatting.Indented;
            xmlSerialisedForm.WriteStartDocument();
            xmlSerialisedForm.WriteStartElement("Form");
            foreach (Control c in cntrls)
                AddChildControls(xmlSerialisedForm, c);

            xmlSerialisedForm.WriteEndElement();
            xmlSerialisedForm.WriteEndDocument();
            xmlSerialisedForm.Flush();
            xmlSerialisedForm.Close();
        }

        private static void AddChildControls(XmlTextWriter xmlSerialisedForm, Control c)
        {
            foreach (Control childCtrl in c.Controls)
            {
                if (childCtrl is not Label && !string.IsNullOrEmpty(childCtrl.Name))
                {
                    xmlSerialisedForm.WriteStartElement("Control");
                    xmlSerialisedForm.WriteAttributeString("Type", childCtrl.GetType().ToString());
                    xmlSerialisedForm.WriteAttributeString("Name", childCtrl.Name);
                    if (childCtrl is MephTextBox txtbox)
                    {
                        xmlSerialisedForm.WriteElementString("Text", txtbox.Text);
                    }
                    else if (childCtrl is MephComboBox combobox)
                    {
                        xmlSerialisedForm.WriteElementString("Text", combobox.Text);
                        xmlSerialisedForm.WriteElementString("SelectedIndex", combobox.SelectedIndex.ToString());
                    }
                    else if (childCtrl is MephListBox lst)
                    {
                        for (int i = 0; i < lst.Items.Count; i++)
                        {
                            xmlSerialisedForm.WriteStartElement("Item");
                            xmlSerialisedForm.WriteAttributeString("Type", lst.Items[i].GetType().ToString());
                            AddChildControls(xmlSerialisedForm, (Control)lst.Items[i]);
                            xmlSerialisedForm.WriteEndElement();
                        }
                    }
                    else if (childCtrl is MephCheckBox checkbox)
                    {
                        xmlSerialisedForm.WriteElementString("Text", checkbox.Text);
                        xmlSerialisedForm.WriteElementString("Checked", checkbox.Checked.ToString());
                    }
                    else if (childCtrl is MephToggleSwitch toggleswitch)
                    {
                        xmlSerialisedForm.WriteElementString("Text", toggleswitch.Text);
                        xmlSerialisedForm.WriteElementString("Checked", toggleswitch.Checked.ToString());
                    }
                    bool visible = (bool)typeof(Control).GetMethod("GetState", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(childCtrl, new object[] { 2 });
                    xmlSerialisedForm.WriteElementString("Visible", visible.ToString());
                    xmlSerialisedForm.WriteElementString("Enabled", childCtrl.Enabled.ToString());
                    if (childCtrl.HasChildren)
                    {
                        if (childCtrl is SplitContainer container)
                        {
                            AddChildControls(xmlSerialisedForm, container.Panel1);
                            AddChildControls(xmlSerialisedForm, container.Panel2);
                        }
                        else
                        {
                            AddChildControls(xmlSerialisedForm, childCtrl);
                        }
                    }
                    xmlSerialisedForm.WriteEndElement();
                }
            }
        }

        public static void Deserialise(List<Control> cntrls, string XmlFileName)
        {
            if (File.Exists(XmlFileName))
            {
                XmlDocument xmlSerialisedForm = new XmlDocument();
                xmlSerialisedForm.Load(XmlFileName);
                XmlNode topLevel = xmlSerialisedForm.ChildNodes[1];
                foreach (XmlNode n in topLevel.ChildNodes)
                    foreach (Control c in cntrls)
                        SetControlProperties(c, n);
            }
        }

        private static void SetControlProperties(Control currentCtrl, XmlNode n)
        {
            string controlName = n.Attributes["Name"].Value;
            string controlType = n.Attributes["Type"].Value;
            Control[] ctrl = currentCtrl.Controls.Find(controlName, true);
            if (ctrl.Length > 0)
            {
                Control ctrlToSet = GetImmediateChildControl(ctrl, currentCtrl);
                if (ctrlToSet != null)
                {
                    if (ctrlToSet.GetType().ToString() == controlType)
                    {
                        switch (controlType)
                        {
                            case "MephTextBox":
                                ((MephTextBox)ctrlToSet).Text = n["Text"].InnerText;
                                break;
                            case "MephComboBox":
                                ((MephComboBox)ctrlToSet).Text = n["Text"].InnerText;
                                ((MephComboBox)ctrlToSet).SelectedIndex = Convert.ToInt32(n["SelectedIndex"].InnerText);
                                break;
                            case "MephListBox":
                                MephListBox lst = (MephListBox)ctrlToSet;
                                lst.Items.Clear();
                                XmlNodeList xnlControls = n.SelectNodes("Item");
                                foreach (XmlNode n2 in xnlControls)
                                {
                                    dynamic item = Activator.CreateInstance(Type.GetType(n2.Attributes["Type"].Value));
                                    lst.Items.Add(item);
                                    foreach (XmlNode n3 in n2.ChildNodes)
                                    {
                                        int count = lst.Items.Count;
                                        SetControlProperties((Control)lst.Items[count - 1], n3);
                                        for (int i = 0; i < count; i++)
                                            lst.Items[i] = lst.Items[i];
                                    }
                                }
                                break;
                            case "MephCheckBox":
                                ((MephCheckBox)ctrlToSet).Text = n["Text"].InnerText;
                                ((MephCheckBox)ctrlToSet).Checked = Convert.ToBoolean(n["Checked"].InnerText);
                                break;
                            case "MephToggleSwitch":
                                ((MephToggleSwitch)ctrlToSet).Text = n["Text"].InnerText;
                                ((MephToggleSwitch)ctrlToSet).Checked = Convert.ToBoolean(n["Checked"].InnerText);
                                break;
                        }
                        ctrlToSet.Visible = Convert.ToBoolean(n["Visible"].InnerText);
                        ctrlToSet.Enabled = Convert.ToBoolean(n["Enabled"].InnerText);
                        if (n.HasChildNodes && ctrlToSet.HasChildren)
                        {
                            XmlNodeList xnlControls = n.SelectNodes("Control");
                            foreach (XmlNode n2 in xnlControls)
                                SetControlProperties(ctrlToSet, n2);
                        }
                    }
                }
            }
        }

        private static Control GetImmediateChildControl(Control[] ctrl, Control currentCtrl)
        {
            Control c = null;
            for (int i = 0; i < ctrl.Length; i++)
            {
                if ((ctrl[i].Parent.Name == currentCtrl.Name) || (currentCtrl is SplitContainer && ctrl[i].Parent.Parent.Name == currentCtrl.Name))
                {
                    c = ctrl[i];
                    break;
                }
            }
            return c;
        }

    }
}