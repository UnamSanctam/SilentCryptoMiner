using System.Collections.Generic;
using System.Windows.Forms;
using System.Xml;

namespace FormLocalization
{
    public static class FormLocalizer
    {

        /* Form Localizer by Unam Sanctam https://github.com/UnamSanctam */

        public static List<string> controlcache = new List<string>();

        public static void WriteDefault(List<Control> cntrls, string XmlFileName)
        {
            XmlTextWriter xmlSerialisedForm = new XmlTextWriter(XmlFileName, System.Text.Encoding.Default);
            xmlSerialisedForm.Formatting = Formatting.Indented;
            xmlSerialisedForm.WriteStartDocument();
            xmlSerialisedForm.WriteStartElement("Localization");
            foreach (Control c in cntrls)
            {
                AddChildControls(xmlSerialisedForm, c);
            }
            xmlSerialisedForm.WriteEndElement();
            xmlSerialisedForm.WriteEndDocument();
            xmlSerialisedForm.Flush();
            xmlSerialisedForm.Close();
        }

        private static void AddChildControls(XmlTextWriter xmlSerialisedForm, Control c)
        {
            foreach (Control childCtrl in c.Controls)
            {
                if (!string.IsNullOrEmpty(childCtrl.Name))
                {
                    if (!controlcache.Contains(childCtrl.Name) && (childCtrl is Label || childCtrl is LinkLabel || childCtrl is MephCheckBox || childCtrl is MephButton))
                    {
                        xmlSerialisedForm.WriteStartElement("Control");
                        xmlSerialisedForm.WriteAttributeString("Name", childCtrl.Name);
                        xmlSerialisedForm.WriteStartElement("Text");
                        xmlSerialisedForm.WriteAttributeString("Lang", "en");
                        xmlSerialisedForm.WriteString(childCtrl.Text);
                        xmlSerialisedForm.WriteEndElement();
                        xmlSerialisedForm.WriteEndElement();

                        controlcache.Add(childCtrl.Name);
                    }
                    if (childCtrl.HasChildren)
                    {
                        if (childCtrl is SplitContainer)
                        {
                            AddChildControls(xmlSerialisedForm, ((SplitContainer)childCtrl).Panel1);
                            AddChildControls(xmlSerialisedForm, ((SplitContainer)childCtrl).Panel2);
                        }
                        else
                        {
                            AddChildControls(xmlSerialisedForm, childCtrl);
                        }
                    }
                }
            }
        }

        public static void TranslateControls(List<Control> cntrls, string xml, string language, string defaultLanguage)
        {
            XmlDocument xmlSerialisedForm = new XmlDocument();
            xmlSerialisedForm.LoadXml(xml);
            XmlNode topLevel = xmlSerialisedForm.ChildNodes[1];
            foreach (XmlNode n in topLevel.ChildNodes)
                foreach (Control c in cntrls)
                    SetControlProperties(c, n, language, defaultLanguage);
        }

        private static void SetControlProperties(Control currentCtrl, XmlNode n, string language, string defaultLanguage)
        {
            string controlName = n.Attributes["Name"].Value;
            Control[] ctrl = currentCtrl.Controls.Find(controlName, true);
            if (ctrl.Length > 0)
                foreach (string lang in new string[] { language, defaultLanguage })
                {
                    XmlNode langnode = n.SelectSingleNode("Text[@Lang='" + lang + "']");
                    if (langnode != null)
                    {
                        ctrl[0].Text = langnode.InnerText;
                        break;
                    }
                }
        }
    }
}