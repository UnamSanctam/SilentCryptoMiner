using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.CompilerServices;
using System.Windows.Forms;

internal enum MouseState : byte
{
    None = 0,
    Over = 1,
    Down = 2,
    Block = 3
}

internal static partial class Draw
{
    public static GraphicsPath RoundRect(Rectangle Rectangle, int Curve)
    {
        var P = new GraphicsPath();
        int ArcRectangleWidth = Curve * 2;
        P.AddArc(new Rectangle(Rectangle.X, Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), -180, 90);
        P.AddArc(new Rectangle(Rectangle.Width - ArcRectangleWidth + Rectangle.X, Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), -90, 90);
        P.AddArc(new Rectangle(Rectangle.Width - ArcRectangleWidth + Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), 0, 90);
        P.AddArc(new Rectangle(Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), 90, 90);
        P.AddLine(new Point(Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y), new Point(Rectangle.X, Curve + Rectangle.Y));
        return P;
    }

    public static GraphicsPath RoundRect(int X, int Y, int Width, int Height, int Curve)
    {
        var Rectangle = new Rectangle(X, Y, Width, Height);
        var P = new GraphicsPath();
        int ArcRectangleWidth = Curve * 2;
        P.AddArc(new Rectangle(Rectangle.X, Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), -180, 90);
        P.AddArc(new Rectangle(Rectangle.Width - ArcRectangleWidth + Rectangle.X, Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), -90, 90);
        P.AddArc(new Rectangle(Rectangle.Width - ArcRectangleWidth + Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), 0, 90);
        P.AddArc(new Rectangle(Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), 90, 90);
        P.AddLine(new Point(Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y), new Point(Rectangle.X, Curve + Rectangle.Y));
        return P;
    }

    public static void InnerGlow(Graphics G, Rectangle Rectangle, Color[] Colors)
    {
        int SubtractTwo = 1;
        int AddOne = 0;
        foreach (var c in Colors)
        {
            G.DrawRectangle(new Pen(new SolidBrush(Color.FromArgb(c.R, c.B, c.G))), Rectangle.X + AddOne, Rectangle.Y + AddOne, Rectangle.Width - SubtractTwo, Rectangle.Height - SubtractTwo);
            SubtractTwo += 2;
            AddOne += 1;
        }
    }

    public static void InnerGlowRounded(Graphics G, Rectangle Rectangle, int Degree, Color[] Colors)
    {
        int SubtractTwo = 1;
        int AddOne = 0;
        foreach (var c in Colors)
        {
            G.DrawPath(new Pen(new SolidBrush(Color.FromArgb(c.R, c.B, c.G))), Draw.RoundRect(Rectangle.X + AddOne, Rectangle.Y + AddOne, Rectangle.Width - SubtractTwo, Rectangle.Height - SubtractTwo, Degree));
            SubtractTwo += 2;
            AddOne += 1;
        }
    }
}

public partial class MephTheme : ContainerControl
{
    private string _subHeader;

    public string SubHeader
    {
        get
        {
            return _subHeader;
        }

        set
        {
            _subHeader = value;
            Invalidate();
        }
    }

    private Color _accentColor;

    public Color AccentColor
    {
        get
        {
            return _accentColor;
        }

        set
        {
            _accentColor = value;
            Invalidate();
        }
    }

    public MephTheme()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.FromArgb(28, 28, 28);
        _subHeader = "Insert Sub Header";
        _accentColor = Color.DarkRed;
        DoubleBuffered = true;
    }

    protected override void OnPaint(System.Windows.Forms.PaintEventArgs e)
    {
        Graphics G = e.Graphics;
        var mainRect = new Rectangle(0, 0, Width, Height);
        base.OnPaint(e);
        G.Clear(Color.Fuchsia);
        // G.SetClip(Draw.RoundRect(New Rectangle(0, 0, Width, Height), 9))

        var c = new Color[] { Color.FromArgb(10, 10, 10), Color.FromArgb(45, 45, 45), Color.FromArgb(40, 40, 40), Color.FromArgb(45, 45, 45), Color.FromArgb(46, 46, 46), Color.FromArgb(47, 47, 47), Color.FromArgb(48, 48, 48), Color.FromArgb(49, 49, 49), Color.FromArgb(50, 50, 50) };
        G.FillRectangle(new SolidBrush(Color.FromArgb(50, 50, 50)), mainRect);
        Draw.InnerGlow(G, mainRect, c);
        var c2 = new Color[] { Color.FromArgb(5, 5, 5), Color.FromArgb(40, 40, 40), Color.FromArgb(41, 41, 41), Color.FromArgb(42, 42, 42), Color.FromArgb(43, 43, 43), Color.FromArgb(44, 44, 44), Color.FromArgb(45, 45, 45) };
        G.FillRectangle(new SolidBrush(Color.FromArgb(45, 45, 45)), new Rectangle(0, 35, Width, 23));
        Draw.InnerGlow(G, new Rectangle(0, 35, Width, 23), c2);
        var accentGradient = new LinearGradientBrush(new Rectangle(0, 36, 11, 21), _accentColor, Color.FromArgb((_accentColor.R >= 10 ? _accentColor.R - 10 : _accentColor.R + 10), (_accentColor.G >= 10 ? _accentColor.G - 10 : _accentColor.G + 10), (_accentColor.B >= 10 ? _accentColor.B - 10 : _accentColor.B + 10)), (short)90);
        G.FillRectangle(accentGradient, new Rectangle(0, 36, 11, 21));
        G.DrawRectangle(new Pen(new SolidBrush(Color.FromArgb(5, 5, 5))), new Rectangle(0, 35, 11, 22));
        G.FillRectangle(accentGradient, new Rectangle(Width - 12, 36, 11, 21));
        G.DrawRectangle(new Pen(new SolidBrush(Color.FromArgb(5, 5, 5))), new Rectangle(Width - 12, 35, 11, 22));
        var gloss = new LinearGradientBrush(new Rectangle(1, 0, Width - 1, 35 / 2), Color.FromArgb(255, Color.FromArgb(90, 90, 90)), Color.FromArgb(255, 71, 71, 71), (short)90);
        G.FillRectangle(gloss, new Rectangle(1, 0, Width - 2, 35 / 2));
        G.DrawLine(new Pen(new SolidBrush(Color.FromArgb(5, 5, 5))), 0, 0, Width, 0);
        G.DrawLine(new Pen(new SolidBrush(Color.FromArgb(150, 150, 150))), 1, 1, Width - 2, 1);
        G.DrawLine(new Pen(new SolidBrush(Color.FromArgb(85, 85, 85))), 1, 34, Width - 2, 34);
        G.DrawLine(new Pen(new SolidBrush(Color.FromArgb(45, 45, 45))), 1, 58, Width - 2, 58);
        var drawFont = new Font("Verdana", 10, FontStyle.Regular);
        G.DrawString(Text, drawFont, new SolidBrush(Color.FromArgb(225, 225, 225)), new Rectangle(0, 0, Width, 35), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
        var subFont = new Font("Verdana", 8, FontStyle.Regular);
        G.DrawString(_subHeader, subFont, new SolidBrush(Color.FromArgb(225, 225, 225)), new Rectangle(0, 35, Width, 23), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
        var controlFont = new Font("Marlett", 10, FontStyle.Regular);
        switch (State)
        {
            case MouseState.None:
                {
                    G.DrawString("r", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-4, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                    G.DrawString("1", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-21, -5, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                    G.DrawString("0", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-38, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                    break;
                }

            case MouseState.Over:
                {
                    if (X > Width - 18 & X < Width - 10 & Y < 18 & Y > 8)
                    {
                        G.DrawString("r", controlFont, new SolidBrush(Color.FromArgb(255, 255, 255)), new Rectangle(-4, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                        G.DrawString("1", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-21, -5, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                        G.DrawString("0", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-38, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                    }
                    else if (X > Width - 36 & X < Width - 25 & Y < 18 & Y > 8)
                    {
                        G.DrawString("r", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-4, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                        G.DrawString("1", controlFont, new SolidBrush(Color.FromArgb(255, 255, 255)), new Rectangle(-21, -5, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                        G.DrawString("0", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-38, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                    }
                    else if (X > Width - 52 & X < Width - 44 & Y < 18 & Y > 8)
                    {
                        G.DrawString("r", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-4, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                        G.DrawString("1", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-21, -5, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                        G.DrawString("0", controlFont, new SolidBrush(Color.FromArgb(255, 255, 255)), new Rectangle(-38, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                    }
                    else
                    {
                        G.DrawString("r", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-4, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                        G.DrawString("1", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-21, -5, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                        G.DrawString("0", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-38, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                    }

                    break;
                }

            case MouseState.Down:
                {
                    G.DrawString("r", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-4, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                    G.DrawString("1", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-21, -5, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                    G.DrawString("0", controlFont, new SolidBrush(Color.FromArgb(178, 178, 178)), new Rectangle(-38, -6, Width, 35), new StringFormat() { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center });
                    break;
                }
        }
    }

    private Point MouseP = new Point(0, 0);
    private bool Cap = false;
    private int MoveHeight = 35;
    private MouseState State = MouseState.None;
    private int X;
    private int Y;

    protected override void OnMouseDown(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button == MouseButtons.Left & new Rectangle(0, 0, Width, MoveHeight).Contains(e.Location) & X < Width - 53)
        {
            Cap = true;
            MouseP = e.Location;
        }
        else if (X > Width - 18 & X < Width - 8 & Y < 18 & Y > 8)
        {
            FindForm().Close();
        }
        else if (X > Width - 36 & X < Width - 25 & Y < 18 & Y > 8)
        {
            if (FindForm().WindowState == FormWindowState.Maximized)
            {
                FindForm().WindowState = FormWindowState.Normal;
            }
            else
            {
            }
        }
        else if (X > Width - 52 & X < Width - 44 & Y < 18 & Y > 8)
        {
            FindForm().WindowState = FormWindowState.Minimized;
        }

        State = MouseState.Down;
        Invalidate();
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        base.OnMouseEnter(e);
        State = MouseState.Over;
        Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        State = MouseState.None;
        Invalidate();
    }

    protected override void OnMouseUp(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseUp(e);
        Cap = false;
        State = MouseState.Over;
        Invalidate();
    }

    protected override void OnMouseMove(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (Cap)
        {
            Parent.Location = new Point(MousePosition.X - MouseP.X, MousePosition.Y - MouseP.Y);
        }

        X = e.Location.X;
        Y = e.Location.Y;
        Invalidate();
    }

    protected override void OnCreateControl()
    {
        base.OnCreateControl();
        ParentForm.FormBorderStyle = FormBorderStyle.None;
        ParentForm.TransparencyKey = Color.Fuchsia;
        ParentForm.Dock = DockStyle.Fill;
        ParentForm.Anchor = AnchorStyles.None;
        ParentForm.Font = new Font("Segoe UI", 9.5f, Font.Style, Font.Unit, Font.GdiCharSet, Font.GdiVerticalFont);
        ParentForm.AutoScaleMode = AutoScaleMode.None;
        Anchor = AnchorStyles.None;
        Font = new Font("Segoe UI", 9.5f, Font.Style, Font.Unit, Font.GdiCharSet, Font.GdiVerticalFont);
        AutoScaleMode = AutoScaleMode.None;
    }
}

public partial class MephButton : Control
{
    #region  MouseStates 
    private MouseState State = MouseState.None;

    protected override void OnMouseDown(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseDown(e);
        State = MouseState.Down;
        Invalidate();
    }

    protected override void OnMouseUp(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseUp(e);
        State = MouseState.Over;
        Invalidate();
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        base.OnMouseEnter(e);
        State = MouseState.Over;
        Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        State = MouseState.None;
        Invalidate();
    }
    #endregion

    public MephButton()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        ForeColor = Color.FromArgb(205, 205, 205);
        DoubleBuffered = true;
    }

    protected override void OnPaint(System.Windows.Forms.PaintEventArgs e)
    {
        var B = new Bitmap(Width, Height);
        Graphics G = Graphics.FromImage(B);
        var ClientRectangle = new Rectangle(0, 0, Width - 1, Height - 1);
        base.OnPaint(e);
        G.Clear(BackColor);
        var drawFont = new Font("Verdana", 8, FontStyle.Regular);
        G.SmoothingMode = SmoothingMode.HighQuality;
        G.FillPath(new SolidBrush(Color.FromArgb(40, 40, 40)), Draw.RoundRect(ClientRectangle, 3));
        G.DrawPath(new Pen(new SolidBrush(Color.FromArgb(15, 15, 15))), Draw.RoundRect(ClientRectangle, 3));
        G.DrawPath(new Pen(new SolidBrush(Color.FromArgb(55, 55, 55))), Draw.RoundRect(new Rectangle(1, 1, Width - 3, Height - 3), 3));
        switch (State)
        {
            case MouseState.None:
                {
                    G.DrawString(Text, drawFont, Brushes.Silver, new Rectangle(0, 0, Width - 1, Height - 1), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
                    break;
                }

            case MouseState.Over:
                {
                    G.DrawString(Text, drawFont, Brushes.White, new Rectangle(0, 0, Width - 1, Height - 1), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
                    break;
                }

            case MouseState.Down:
                {
                    G.DrawString(Text, drawFont, Brushes.Gray, new Rectangle(0, 0, Width - 1, Height - 1), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
                    break;
                }
        }

        e.Graphics.DrawImage(B, 0, 0);
        G.Dispose();
        B.Dispose();
    }
}

public partial class MephGroupBox : ContainerControl
{
    public enum HeaderLine
    {
        Enabled,
        Disabled
    }

    private HeaderLine _HeaderLine;

    public HeaderLine Header_Line
    {
        get
        {
            return _HeaderLine;
        }

        set
        {
            _HeaderLine = value;
            Invalidate();
        }
    }

    public MephGroupBox()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        ForeColor = Color.FromArgb(205, 205, 205);
        Size = new Size(174, 115);
        _HeaderLine = HeaderLine.Enabled;
        DoubleBuffered = true;
    }

    protected override void OnPaint(System.Windows.Forms.PaintEventArgs e)
    {
        var B = new Bitmap(Width, Height);
        Graphics G = Graphics.FromImage(B);
        var ClientRectangle = new Rectangle(0, 0, Width - 1, Height - 1);
        base.OnPaint(e);
        G.Clear(BackColor);
        var drawFont = new Font("Verdana", 8, FontStyle.Regular);
        G.SmoothingMode = SmoothingMode.HighQuality;
        var c = new Color[] { Color.FromArgb(20, 20, 20), Color.FromArgb(45, 45, 45), Color.FromArgb(40, 40, 40), Color.FromArgb(45, 45, 45), Color.FromArgb(46, 46, 46), Color.FromArgb(47, 47, 47), Color.FromArgb(48, 48, 48), Color.FromArgb(49, 49, 49), Color.FromArgb(50, 50, 50) };
        G.FillRectangle(new SolidBrush(Color.FromArgb(50, 50, 50)), ClientRectangle);
        Draw.InnerGlow(G, ClientRectangle, c);
        switch (_HeaderLine)
        {
            case HeaderLine.Enabled:
                {
                    G.DrawLine(new Pen(new SolidBrush(Color.FromArgb(45, 45, 45))), 16, 29, Width - 17, 29);
                    G.DrawLine(new Pen(new SolidBrush(Color.FromArgb(20, 20, 20))), 15, 30, Width - 16, 30);
                    G.DrawLine(new Pen(new SolidBrush(Color.FromArgb(45, 45, 45))), 16, 31, Width - 17, 31);
                    break;
                }

            case HeaderLine.Disabled:
                {
                    break;
                }
        }

        G.DrawString(Text, drawFont, Brushes.Silver, new Rectangle(0, 3, Width - 1, 27), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
        e.Graphics.DrawImage(B, 0, 0);
        G.Dispose();
        B.Dispose();
    }
}

[DefaultEvent("CheckedChanged")]
public partial class MephToggleSwitch : Control
{

    #region  Control Help - MouseState & Flicker Control
    private MouseState State = MouseState.None;

    protected override void OnMouseEnter(EventArgs e)
    {
        base.OnMouseEnter(e);
        State = MouseState.Over;
        Invalidate();
    }

    protected override void OnMouseDown(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseDown(e);
        State = MouseState.Down;
        Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        State = MouseState.None;
        Invalidate();
    }

    protected override void OnMouseUp(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseUp(e);
        State = MouseState.Over;
        Invalidate();
    }

    protected override void OnTextChanged(EventArgs e)
    {
        base.OnTextChanged(e);
        Invalidate();
    }

    private bool _Checked;

    public bool Checked
    {
        get
        {
            return _Checked;
        }

        set
        {
            _Checked = value;
            Invalidate();
        }
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        Height = 24;
        Width = 50;
    }

    protected override void OnClick(EventArgs e)
    {
        _Checked = !_Checked;
        CheckedChanged?.Invoke(this);
        base.OnClick(e);
    }

    public event CheckedChangedEventHandler CheckedChanged;

    public delegate void CheckedChangedEventHandler(object sender);
    #endregion

    public MephToggleSwitch() : base()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor | ControlStyles.OptimizedDoubleBuffer, true);
        BackColor = Color.Transparent;
        ForeColor = Color.Black;
        Size = new Size(50, 24);
        DoubleBuffered = true;
    }

    protected override void OnPaint(System.Windows.Forms.PaintEventArgs e)
    {
        var B = new Bitmap(Width, Height);
        Graphics G = Graphics.FromImage(B);
        var onoffRect = new Rectangle(0, 0, Width - 1, Height - 1);
        G.SmoothingMode = SmoothingMode.HighQuality;
        G.CompositingQuality = CompositingQuality.HighQuality;
        G.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
        G.Clear(Color.Transparent);
        var bodyGrad = new LinearGradientBrush(onoffRect, Color.FromArgb(40, 40, 40), Color.FromArgb(45, 45, 45), (short)90);
        G.FillPath(bodyGrad, Draw.RoundRect(onoffRect, 4));
        G.DrawPath(new Pen(Color.FromArgb(15, 15, 15)), Draw.RoundRect(onoffRect, 4));
        G.DrawPath(new Pen(Color.FromArgb(50, 50, 50)), Draw.RoundRect(new Rectangle(1, 1, Width - 3, Height - 3), 4));
        if (Checked)
        {
            G.FillPath(new SolidBrush(Color.FromArgb(60, Color.Green)), Draw.RoundRect(new Rectangle(Width / 2 - 7, 2, Width - 25, Height - 5), 4));
            G.FillPath(new SolidBrush(Color.FromArgb(35, 35, 35)), Draw.RoundRect(new Rectangle(Width / 2 - 5, 2, Width - 23, Height - 5), 4));
            G.DrawPath(new Pen(new SolidBrush(Color.FromArgb(20, 20, 20))), Draw.RoundRect(new Rectangle(Width / 2 - 5, 2, Width - 23, Height - 5), 4));
            switch (State)
            {
                case MouseState.None:
                    {
                        G.DrawString("On", new Font("Tahoma", 8, FontStyle.Regular), Brushes.Silver, new Point(34, Height - 12), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
                        break;
                    }

                case MouseState.Over:
                    {
                        G.DrawString("On", new Font("Tahoma", 8, FontStyle.Regular), Brushes.White, new Point(34, Height - 12), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
                        break;
                    }

                case MouseState.Down:
                    {
                        G.DrawString("On", new Font("Tahoma", 8, FontStyle.Regular), Brushes.Silver, new Point(34, Height - 12), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
                        break;
                    }
            }
        }
        else
        {
            G.FillPath(new SolidBrush(Color.FromArgb(80, Color.Red)), Draw.RoundRect(new Rectangle(4, 2, 25, Height - 5), 4));
            G.FillPath(new SolidBrush(Color.FromArgb(35, 35, 35)), Draw.RoundRect(new Rectangle(2, 2, 25, Height - 5), 4));
            G.DrawPath(new Pen(new SolidBrush(Color.FromArgb(20, 20, 20))), Draw.RoundRect(new Rectangle(2, 2, 25, Height - 5), 4));
            switch (State)
            {
                case MouseState.None:
                    {
                        G.DrawString("Off", new Font("Tahoma", 8, FontStyle.Regular), Brushes.Silver, new Point(14, Height - 11), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
                        break;
                    }

                case MouseState.Over:
                    {
                        G.DrawString("Off", new Font("Tahoma", 8, FontStyle.Regular), Brushes.White, new Point(14, Height - 11), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
                        break;
                    }

                case MouseState.Down:
                    {
                        G.DrawString("Off", new Font("Tahoma", 8, FontStyle.Regular), Brushes.Silver, new Point(14, Height - 11), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
                        break;
                    }
            }
        }

        e.Graphics.DrawImage(B, 0, 0);
        G.Dispose();
        B.Dispose();
    }
}

public partial class MephTextBox : Control
{

    public MephTextBox() : base()
    {
        txtbox = new TextBox();
        TextChanged += TextChng;
        NewTextBox();
        Controls.Add(txtbox);
        Text = "";
        BackColor = Color.FromArgb(50, 50, 50);
        ForeColor = Color.Silver;
        Size = new Size(135, 24);
        DoubleBuffered = true;
    }

    private TextBox _txtbox;

    private TextBox txtbox
    {
        [MethodImpl(MethodImplOptions.Synchronized)]
        get
        {
            return _txtbox;
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        set
        {
            if (_txtbox != null)
            {
                _txtbox.TextChanged -= TextChngTxtBox;
            }

            _txtbox = value;
            if (_txtbox != null)
            {
                _txtbox.TextChanged += TextChngTxtBox;
            }
        }
    }

    #region  Control Help - Properties & Flicker Control 
    private bool _passmask = false;

    public bool UseSystemPasswordChar
    {
        get
        {
            return _passmask;
        }

        set
        {
            txtbox.UseSystemPasswordChar = UseSystemPasswordChar;
            _passmask = value;
            Invalidate();
        }
    }

    private int _maxchars = 32767;

    public int MaxLength
    {
        get
        {
            return _maxchars;
        }

        set
        {
            _maxchars = value;
            txtbox.MaxLength = MaxLength;
            Invalidate();
        }
    }

    private HorizontalAlignment _align;

    public HorizontalAlignment TextAlignment
    {
        get
        {
            return _align;
        }

        set
        {
            _align = value;
            Invalidate();
        }
    }

    private bool _multiline = false;

    public bool MultiLine
    {
        get
        {
            return _multiline;
        }

        set
        {
            _multiline = value;
            Invalidate();
        }
    }

    private bool _wordwrap = false;

    public bool WordWrap
    {
        get
        {
            return _wordwrap;
        }

        set
        {
            _wordwrap = value;
            Invalidate();
        }
    }

    private bool _readonly = false;

    public bool ReadOnly
    {
        get
        {
            return _readonly;
        }

        set
        {
            _readonly = value;
            Invalidate();
        }
    }

    protected override void OnPaintBackground(System.Windows.Forms.PaintEventArgs pevent)
    {
    }

    protected override void OnTextChanged(EventArgs e)
    {
        base.OnTextChanged(e);
        Invalidate();
    }

    protected override void OnBackColorChanged(EventArgs e)
    {
        base.OnBackColorChanged(e);
        txtbox.BackColor = BackColor;
        Invalidate();
    }

    protected override void OnForeColorChanged(EventArgs e)
    {
        base.OnForeColorChanged(e);
        txtbox.ForeColor = ForeColor;
        Invalidate();
    }

    protected override void OnFontChanged(EventArgs e)
    {
        base.OnFontChanged(e);
        txtbox.Font = Font;
    }

    protected override void OnGotFocus(EventArgs e)
    {
        base.OnGotFocus(e);
        txtbox.Focus();
    }

    public void TextChngTxtBox(object sender, EventArgs e)
    {
        Text = txtbox.Text;
    }

    public void TextChng(object sender, EventArgs e)
    {
        txtbox.Text = Text;
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        if (MultiLine == false)
        {
            Height = 24;
        }
    }

    public void NewTextBox()
    {
        {
            var withBlock = txtbox;
            withBlock.Multiline = MultiLine;
            withBlock.BackColor = Color.FromArgb(50, 50, 50);
            withBlock.ForeColor = ForeColor;
            withBlock.Text = string.Empty;
            withBlock.TextAlign = HorizontalAlignment.Center;
            withBlock.BorderStyle = BorderStyle.None;
            withBlock.Location = new Point(5, 4);
            withBlock.Font = new Font("Verdana", 8, FontStyle.Regular);
            withBlock.WordWrap = WordWrap;
            withBlock.Size = new Size(Width - 10, Height - 11);
            withBlock.UseSystemPasswordChar = UseSystemPasswordChar;
            withBlock.ReadOnly = ReadOnly;
        }
    }

    protected override void OnPaint(System.Windows.Forms.PaintEventArgs e)
    {
        var B = new Bitmap(Width, Height);
        Graphics G = Graphics.FromImage(B);
        G.SmoothingMode = SmoothingMode.HighQuality;
        var ClientRectangle = new Rectangle(0, 0, Width - 1, Height - 1);
        {
            var withBlock = txtbox;
            withBlock.Multiline = MultiLine;
            if (MultiLine == false)
            {
                Height = txtbox.Height + 11;
            }
            else
            {
                txtbox.Height = Height - 11;
            }
            withBlock.WordWrap = WordWrap;
            withBlock.Width = Width - 10;
            withBlock.TextAlign = TextAlignment;
            withBlock.UseSystemPasswordChar = UseSystemPasswordChar;
            withBlock.ReadOnly = ReadOnly;
        }

        G.Clear(BackColor);
        var c = new Color[] { Color.FromArgb(20, 20, 20), Color.FromArgb(40, 40, 40), Color.FromArgb(45, 45, 45), Color.FromArgb(46, 46, 46), Color.FromArgb(47, 47, 47), Color.FromArgb(48, 48, 48), Color.FromArgb(49, 49, 49), Color.FromArgb(50, 50, 50) };
        G.FillPath(new SolidBrush(Color.FromArgb(50, 50, 50)), Draw.RoundRect(ClientRectangle, 3));
        Draw.InnerGlowRounded(G, ClientRectangle, 3, c);
        e.Graphics.DrawImage(B, 0, 0);
        G.Dispose();
        B.Dispose();
    }
}

public partial class MephListBox : ListBox
{
    public MephListBox() : base()
    {
        nlistbox = new ListBox();
        SetStyle(ControlStyles.UserPaint, true);
        DoubleBuffered = true;
        {
            var withBlock = nlistbox;
            withBlock.BackColor = Color.FromArgb(50, 50, 50);
            withBlock.ForeColor = Color.Silver;
            withBlock.BorderStyle = BorderStyle.None;
            withBlock.IntegralHeight = false;
            withBlock.Location = new Point(Location.X + 5, Location.Y + 5);
        }

        BackColor = Color.FromArgb(50, 50, 50);
        ForeColor = Color.Silver;
        BorderStyle = BorderStyle.None;
        Controls.Add(nlistbox);
    }

    private ListBox nlistbox;

    public new int ItemHeight
    {
        get
        {
            return nlistbox.ItemHeight;
        }

        set
        {
            nlistbox.ItemHeight = value;
            Invalidate();
        }
    }

    public new bool FormattingEnabled
    {
        get
        {
            return nlistbox.FormattingEnabled;
        }

        set
        {
            nlistbox.FormattingEnabled = value;
            Invalidate();
        }
    }

    public new ObjectCollection Items
    {
        get
        {
            return nlistbox.Items;
        }

        set
        {
            nlistbox.Items.Clear();
            nlistbox.Items.AddRange(value);
            Invalidate();
        }
    }

    public new object SelectedItem
    {
        get
        {
            return nlistbox.SelectedItem;
        }
    }

    public new int SelectedIndex
    {
        get
        {
            return nlistbox.SelectedIndex;
        }

        set
        {
            nlistbox.SelectedIndex = value;
            Invalidate();
        }
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        nlistbox.Size = new Size(Width - 10, Height - 10);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var B = new Bitmap(Width, Height);
        Graphics G = Graphics.FromImage(B);
        G.SmoothingMode = SmoothingMode.HighQuality;
        var ClientRectangle = new Rectangle(0, 0, Width - 1, Height - 1);
        G.Clear(BackColor);
        var c = new Color[] { Color.FromArgb(20, 20, 20), Color.FromArgb(40, 40, 40), Color.FromArgb(45, 45, 45), Color.FromArgb(46, 46, 46), Color.FromArgb(47, 47, 47), Color.FromArgb(48, 48, 48), Color.FromArgb(49, 49, 49), Color.FromArgb(50, 50, 50) };
        G.FillPath(new SolidBrush(Color.FromArgb(50, 50, 50)), Draw.RoundRect(ClientRectangle, 3));
        Draw.InnerGlowRounded(G, ClientRectangle, 3, c);
        e.Graphics.DrawImage(B, 0, 0);
        G.Dispose();
        B.Dispose();
    }
}

public partial class MephProgressBar : Control
{

    #region  Control Help - Properties & Flicker Control 
    private int OFS = 0;
    private int Speed = 50;
    private int _Maximum = 100;

    public int Maximum
    {
        get
        {
            return _Maximum;
        }

        set
        {
            switch (value)
            {
                case var @case when @case < _Value:
                    {
                        _Value = value;
                        break;
                    }
            }

            _Maximum = value;
            Invalidate();
        }
    }

    private int _Value = 0;

    public int Value
    {
        get
        {
            switch (_Value)
            {
                case 0:
                    {
                        return 0;
                    }

                default:
                    {
                        return _Value;
                    }
            }
        }

        set
        {
            switch (value)
            {
                case var @case when @case > _Maximum:
                    {
                        value = _Maximum;
                        break;
                    }
            }

            _Value = value;
            Invalidate();
        }
    }

    private bool _ShowPercentage = false;

    public bool ShowPercentage
    {
        get
        {
            return _ShowPercentage;
        }

        set
        {
            _ShowPercentage = value;
            Invalidate();
        }
    }

    protected override void CreateHandle()
    {
        base.CreateHandle();
    }

    public void Animate()
    {
        while (true)
        {
            if (OFS <= Width)
            {
                OFS += 1;
            }
            else
            {
                OFS = 0;
            }

            Invalidate();
            System.Threading.Thread.Sleep(Speed);
        }
    }
    #endregion

    public MephProgressBar() : base()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
    }

    protected override void OnPaint(System.Windows.Forms.PaintEventArgs e)
    {
        base.OnPaint(e);
        var B = new Bitmap(Width, Height);
        Graphics G = Graphics.FromImage(B);
        G.SmoothingMode = SmoothingMode.HighQuality;
        int intValue = _Value / _Maximum * Width;
        G.Clear(BackColor);
        var percentColor = new SolidBrush(Color.White);
        var c = new Color[] { Color.FromArgb(20, 20, 20), Color.FromArgb(40, 40, 40), Color.FromArgb(45, 45, 45), Color.FromArgb(46, 46, 46), Color.FromArgb(47, 47, 47), Color.FromArgb(48, 48, 48), Color.FromArgb(49, 49, 49), Color.FromArgb(50, 50, 50) };
        G.FillPath(new SolidBrush(Color.FromArgb(50, 50, 50)), Draw.RoundRect(new Rectangle(0, 0, Width - 1, Height - 1), 3));
        Draw.InnerGlowRounded(G, ClientRectangle, 3, c);

        // //// Bar Fill
        if (!(intValue == 0))
        {
            G.FillPath(new LinearGradientBrush(new Rectangle(1, 1, intValue, Height - 3), Color.FromArgb(30, 30, 30), Color.FromArgb(35, 35, 35), (short)90), Draw.RoundRect(new Rectangle(1, 1, intValue, Height - 3), 2));
            G.DrawPath(new Pen(Color.FromArgb(45, 45, 45)), Draw.RoundRect(new Rectangle(1, 1, intValue, Height - 3), 2));
            // G.DrawLine(New Pen(New SolidBrush(Color.FromArgb(15, 15, 15))), intValue + 1, 3, intValue + 1, Height - 4)
            percentColor = new SolidBrush(Color.White);
        }

        if (_ShowPercentage)
        {
            G.DrawString(Convert.ToString(string.Concat(Value, "%")), new Font("Tahoma", 9, FontStyle.Bold), percentColor, new Rectangle(0, 1, Width - 1, Height - 1), new StringFormat() { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center });
        }

        e.Graphics.DrawImage(B, 0, 0);
        G.Dispose();
        B.Dispose();
    }
}

[DefaultEvent("CheckedChanged")]
public partial class MephRadioButton : Control
{

    #region  Control Help - MouseState & Flicker Control
    protected override void OnMouseEnter(EventArgs e)
    {
        base.OnMouseEnter(e);
        Invalidate();
    }

    protected override void OnMouseDown(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        Invalidate();
    }

    protected override void OnMouseUp(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseUp(e);
        Invalidate();
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        Height = 24;
    }

    protected override void OnTextChanged(EventArgs e)
    {
        base.OnTextChanged(e);
        Invalidate();
    }

    private bool _Checked;

    public bool Checked
    {
        get
        {
            return _Checked;
        }

        set
        {
            _Checked = value;
            InvalidateControls();
            CheckedChanged?.Invoke(this);
            Invalidate();
        }
    }

    protected override void OnClick(EventArgs e)
    {
        if (!_Checked)
            Checked = true;
        base.OnClick(e);
    }

    public event CheckedChangedEventHandler CheckedChanged;

    public delegate void CheckedChangedEventHandler(object sender);

    protected override void OnCreateControl()
    {
        base.OnCreateControl();
        InvalidateControls();
    }

    private void InvalidateControls()
    {
        if (!IsHandleCreated || !_Checked)
            return;
        foreach (Control C in Parent.Controls)
        {
            if (!ReferenceEquals(C, this) && C is MephRadioButton)
            {
                ((MephRadioButton)C).Checked = false;
            }
        }
    }

    private Color _accentColor;

    public Color AccentColor
    {
        get
        {
            return _accentColor;
        }

        set
        {
            _accentColor = value;
            Invalidate();
        }
    }
    #endregion

    public MephRadioButton() : base()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        ForeColor = Color.Black;
        Size = new Size(150, 24);
        _accentColor = Color.Maroon;
        DoubleBuffered = true;
    }

    protected override void OnPaint(System.Windows.Forms.PaintEventArgs e)
    {
        var B = new Bitmap(Width, Height);
        Graphics G = Graphics.FromImage(B);
        var radioBtnRectangle = new Rectangle(0, 0, Height - 1, Height - 1);
        var InnerRect = new Rectangle(5, 5, Height - 11, Height - 11);
        G.SmoothingMode = SmoothingMode.HighQuality;
        G.CompositingQuality = CompositingQuality.HighQuality;
        G.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
        G.Clear(BackColor);
        var bgGrad = new LinearGradientBrush(radioBtnRectangle, Color.FromArgb(50, 50, 50), Color.FromArgb(40, 40, 40), (short)90);
        G.FillRectangle(bgGrad, radioBtnRectangle);
        G.DrawRectangle(new Pen(Color.FromArgb(20, 20, 20)), radioBtnRectangle);
        G.DrawRectangle(new Pen(Color.FromArgb(55, 55, 55)), new Rectangle(1, 1, Height - 3, Height - 3));
        if (Checked)
        {
            var fillGradient = new LinearGradientBrush(InnerRect, _accentColor, Color.FromArgb(_accentColor.R, _accentColor.G, _accentColor.B), (short)90);
            G.FillRectangle(fillGradient, InnerRect);
            G.DrawRectangle(new Pen(Color.FromArgb(25, 25, 25)), InnerRect);
        }

        var drawFont = new Font("Tahoma", 10, FontStyle.Bold);
        Brush nb = new SolidBrush(Color.FromArgb(200, 200, 200));
        G.DrawString(Text, drawFont, nb, new Point(28, 12), new StringFormat() { Alignment = StringAlignment.Near, LineAlignment = StringAlignment.Center });
        e.Graphics.DrawImage(B, 0, 0);
        G.Dispose();
        B.Dispose();
    }
}

public partial class MephComboBox : ComboBox
{
    #endregion

    public MephComboBox() : base()
    {
        this.DrawItem += ReplaceItem;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.DoubleBuffer | ControlStyles.SupportsTransparentBackColor, true);
        DrawMode = DrawMode.OwnerDrawFixed;
        BackColor = Color.Transparent;
        ForeColor = Color.Silver;
        Font = new Font("Verdana", 8, FontStyle.Regular);
        DropDownStyle = ComboBoxStyle.DropDownList;
        DoubleBuffered = true;
        Size = new Size(Width, 21);
        ItemHeight = 16;
    }
    #region  Control Help - Properties & Flicker Control 
    private int _StartIndex = 0;

    public int StartIndex
    {
        get
        {
            return _StartIndex;
        }

        set
        {
            _StartIndex = value;
            try
            {
                base.SelectedIndex = value;
            }
            catch
            {
            }

            Invalidate();
        }
    }

    public override System.Drawing.Rectangle DisplayRectangle
    {
        get
        {
            return base.DisplayRectangle;
        }
    }

    public void ReplaceItem(object sender, System.Windows.Forms.DrawItemEventArgs e)
    {
        e.DrawBackground();
        try
        {
            if ((e.State & DrawItemState.Selected) == DrawItemState.Selected)
            {
                e.Graphics.FillRectangle(new SolidBrush(_highlightColor), e.Bounds);
                var gloss = new LinearGradientBrush(e.Bounds, Color.FromArgb(30, Color.White), Color.FromArgb(0, Color.White), 90); // Highlight Gloss/Color
                e.Graphics.FillRectangle(gloss, new Rectangle(new Point(e.Bounds.X, e.Bounds.Y), new Size(e.Bounds.Width, e.Bounds.Height))); // Drop Background
                e.Graphics.DrawRectangle(new Pen(Color.FromArgb(90, Color.Black)) { DashStyle = DashStyle.Solid }, new Rectangle(e.Bounds.X, e.Bounds.Y, e.Bounds.Width - 1, e.Bounds.Height - 1));
            }
            else
            {
                e.Graphics.FillRectangle(new SolidBrush(Color.FromArgb(40, 40, 40)), e.Bounds);
            }

            using (var b = new SolidBrush(Color.Silver))
            {
                e.Graphics.DrawString(GetItemText(Items[e.Index]), e.Font, b, new Rectangle(e.Bounds.X + 2, e.Bounds.Y, e.Bounds.Width - 4, e.Bounds.Height));
            }
        }
        catch
        {
        }

        e.DrawFocusRectangle();
    }

    protected void DrawTriangle(Color Clr, Point FirstPoint, Point SecondPoint, Point ThirdPoint, Point FirstPoint2, Point SecondPoint2, Point ThirdPoint2, Graphics G)
    {
        var points = new List<Point>
        {
            FirstPoint,
            SecondPoint,
            ThirdPoint
        };
        G.FillPolygon(new SolidBrush(Clr), points.ToArray());
        G.DrawPolygon(new Pen(new SolidBrush(Color.FromArgb(25, 25, 25))), points.ToArray());
        var points2 = new List<Point>
        {
            FirstPoint2,
            SecondPoint2,
            ThirdPoint2
        };
        G.FillPolygon(new SolidBrush(Clr), points2.ToArray());
        G.DrawPolygon(new Pen(new SolidBrush(Color.FromArgb(25, 25, 25))), points2.ToArray());
    }

    private Color _highlightColor = Color.FromArgb(55, 55, 55);

    public Color ItemHighlightColor
    {
        get
        {
            return _highlightColor;
        }

        set
        {
            _highlightColor = value;
            Invalidate();
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var B = new Bitmap(Width, Height);
        Graphics G = Graphics.FromImage(B);
        G.SmoothingMode = SmoothingMode.HighQuality;
        G.Clear(BackColor);
        var bodyGradNone = new LinearGradientBrush(new Rectangle(0, 0, Width - 1, Height - 2), Color.FromArgb(40, 40, 40), Color.FromArgb(40, 40, 40), (short)90);
        G.FillPath(bodyGradNone, Draw.RoundRect(new Rectangle((int)bodyGradNone.Rectangle.X, (int)bodyGradNone.Rectangle.Y, (int)bodyGradNone.Rectangle.Width, (int)bodyGradNone.Rectangle.Height), 3));
        var bodyInBorderNone = new LinearGradientBrush(new Rectangle(0, 0, Width - 1, Height - 3), Color.FromArgb(40, 40, 40), Color.FromArgb(40, 40, 40), (short)90);
        G.DrawPath(new Pen(bodyInBorderNone), Draw.RoundRect(new Rectangle(1, 1, Width - 3, Height - 4), 3));
        G.DrawPath(new Pen(Color.FromArgb(20, 20, 20)), Draw.RoundRect(new Rectangle(0, 0, Width - 1, Height - 1), 3)); // Outer Line
        G.DrawPath(new Pen(Color.FromArgb(55, 55, 55)), Draw.RoundRect(new Rectangle(1, 1, Width - 3, Height - 3), 3)); // Inner Line
        DrawTriangle(Color.FromArgb(60, 60, 60), new Point(Width - 14, 12), new Point(Width - 7, 12), new Point(Width - 11, 16), new Point(Width - 14, 10), new Point(Width - 7, 10), new Point(Width - 11, 5), G); // Triangle Fill Color

        // Draw Separator line
        G.DrawLine(new Pen(Color.FromArgb(45, 45, 45)), new Point(Width - 21, 2), new Point(Width - 21, Height - 3));
        G.DrawLine(new Pen(Color.FromArgb(55, 55, 55)), new Point(Width - 20, 1), new Point(Width - 20, Height - 3));
        G.DrawLine(new Pen(Color.FromArgb(45, 45, 45)), new Point(Width - 19, 2), new Point(Width - 19, Height - 3));
        try
        {
            G.DrawString(Text, Font, new SolidBrush(ForeColor), new Rectangle(5, 0, Width - 20, Height), new StringFormat() { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Near });
        }
        catch
        {
        }

        e.Graphics.DrawImage(B, 0, 0);
        G.Dispose();
        B.Dispose();
    }
    #endregion
}

internal partial class MephTabcontrol : TabControl
{
    public GraphicsPath RoundRect(Rectangle Rectangle, int Curve)
    {
        var P = new GraphicsPath();
        int ArcRectangleWidth = Curve * 2;
        P.AddArc(new Rectangle(Rectangle.X, Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), -180, 90);
        P.AddArc(new Rectangle(Rectangle.Width - ArcRectangleWidth + Rectangle.X, Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), -90, 90);
        P.AddArc(new Rectangle(Rectangle.Width - ArcRectangleWidth + Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), 0, 90);
        P.AddArc(new Rectangle(Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), 90, 90);
        P.AddLine(new Point(Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y), new Point(Rectangle.X, Curve + Rectangle.Y));
        return P;
    }

    public GraphicsPath RoundRect(int X, int Y, int Width, int Height, int Curve)
    {
        var Rectangle = new Rectangle(X, Y, Width, Height);
        var P = new GraphicsPath();
        int ArcRectangleWidth = Curve * 2;
        P.AddArc(new Rectangle(Rectangle.X, Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), -180, 90);
        P.AddArc(new Rectangle(Rectangle.Width - ArcRectangleWidth + Rectangle.X, Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), -90, 90);
        P.AddArc(new Rectangle(Rectangle.Width - ArcRectangleWidth + Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), 0, 90);
        P.AddArc(new Rectangle(Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y, ArcRectangleWidth, ArcRectangleWidth), 90, 90);
        P.AddLine(new Point(Rectangle.X, Rectangle.Height - ArcRectangleWidth + Rectangle.Y), new Point(Rectangle.X, Curve + Rectangle.Y));
        return P;
    }

    public MephTabcontrol()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.DoubleBuffer, true);
        DoubleBuffered = true;
        SizeMode = TabSizeMode.Fixed;
        ItemSize = new Size(35, 85);
        Font = new Font("Segoe UI", 9.5f, Font.Style, Font.Unit, Font.GdiCharSet, Font.GdiVerticalFont);
    }

    protected override void CreateHandle()
    {
        base.CreateHandle();
        Alignment = TabAlignment.Left;
    }

    public Pen ToPen(Color color)
    {
        return new Pen(color);
    }

    public Brush ToBrush(Color color)
    {
        return new SolidBrush(color);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var B = new Bitmap(Width, Height);
        Graphics G = Graphics.FromImage(B);
        var FF = new Font("Verdana", 8, FontStyle.Regular);
        try
        {
            SelectedTab.BackColor = Color.FromArgb(50, 50, 50);
        }
        catch
        {
        }

        G.Clear(Parent.FindForm().BackColor);
        G.FillRectangle(new SolidBrush(Color.FromArgb(50, 50, 50)), new Rectangle(0, 0, ItemSize.Height, Height - 1)); // Full Tab Background
        for (int i = 0, loopTo = TabCount - 1; i <= loopTo; i++)
        {
            if (i == SelectedIndex)
            {
                var x2 = new Rectangle(new Point(GetTabRect(i).Location.X - 2, GetTabRect(i).Location.Y - 2), new Size(GetTabRect(i).Width + 3, GetTabRect(i).Height - 1));
                var myBlend = new ColorBlend();
                myBlend.Colors = new[] { Color.FromArgb(50, 50, 50), Color.FromArgb(50, 50, 50), Color.FromArgb(50, 50, 50) }; // Full Tab Background Gradient Accents
                myBlend.Positions = new[] { 0.0f, 0.5f, 1.0f };
                var lgBrush = new LinearGradientBrush(x2, Color.Black, Color.Black, 90.0f)
                {
                    InterpolationColors = myBlend
                };
                G.FillRectangle(lgBrush, x2);
                // G.DrawRectangle(New Pen(Color.FromArgb(20, 20, 20)), x2) 'Full Tab Highlight Outline
                var tabRect = new Rectangle(GetTabRect(i).Location.X + 4, GetTabRect(i).Location.Y + 2, GetTabRect(i).Size.Width + 10, GetTabRect(i).Size.Height - 11);
                G.FillPath(new SolidBrush(Color.FromArgb(50, 50, 50)), RoundRect(tabRect, 4)); // Highlight Fill Background
                var cFull = new Color[] { Color.FromArgb(20, 20, 20), Color.FromArgb(40, 40, 40), Color.FromArgb(45, 45, 45), Color.FromArgb(46, 46, 46), Color.FromArgb(47, 47, 47), Color.FromArgb(48, 48, 48), Color.FromArgb(49, 49, 49), Color.FromArgb(50, 50, 50) };
                Draw.InnerGlow(G, new Rectangle(0, 0, ItemSize.Height + 3, Height - 1), cFull); // Main Left Box Outline
                var cHighlight = new Color[] { Color.FromArgb(20, 20, 20), Color.FromArgb(40, 40, 40), Color.FromArgb(45, 45, 45), Color.FromArgb(46, 46, 46), Color.FromArgb(47, 47, 47), Color.FromArgb(48, 48, 48), Color.FromArgb(49, 49, 49), Color.FromArgb(50, 50, 50) };
                Draw.InnerGlowRounded(G, tabRect, 4, cHighlight); // Fill HighLight Inner
                G.SmoothingMode = SmoothingMode.HighQuality;
                // Dim p() As Point = {New Point(ItemSize.Height - 3, GetTabRect(i).Location.Y + 20), New Point(ItemSize.Height + 4, GetTabRect(i).Location.Y + 14), New Point(ItemSize.Height + 4, GetTabRect(i).Location.Y + 27)}
                // G.FillPolygon(Brushes.White, p)

                if (!(ImageList is null))
                {
                    try
                    {
                        if (!(ImageList.Images[TabPages[i].ImageIndex] is null))
                        {
                            G.DrawImage(ImageList.Images[TabPages[i].ImageIndex], new Point(x2.Location.X + 8, x2.Location.Y + 6));
                            G.DrawString("      " + TabPages[i].Text.ToUpper(), new Font(Font.FontFamily, Font.Size, FontStyle.Regular), Brushes.White, new Rectangle(x2.X, x2.Y - 1, x2.Width, x2.Height), new StringFormat() { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Center });
                        }
                        else
                        {
                            G.DrawString(TabPages[i].Text, FF, Brushes.White, new Rectangle(x2.X, x2.Y - 1, x2.Width, x2.Height), new StringFormat() { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Center });
                        }
                    }
                    catch
                    {
                        G.DrawString(TabPages[i].Text, FF, Brushes.White, new Rectangle(x2.X, x2.Y - 1, x2.Width, x2.Height), new StringFormat() { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Center });
                    }
                }
                else
                {
                    G.DrawString(TabPages[i].Text, FF, Brushes.White, new Rectangle(x2.X, x2.Y - 1, x2.Width, x2.Height), new StringFormat() { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Center });
                }

                G.DrawLine(new Pen(Color.FromArgb(96, 110, 121)), new Point(x2.Location.X - 1, x2.Location.Y - 1), new Point(x2.Location.X, x2.Location.Y));
                G.DrawLine(new Pen(Color.FromArgb(96, 110, 121)), new Point(x2.Location.X - 1, x2.Bottom - 1), new Point(x2.Location.X, x2.Bottom));
            }
            else
            {
                var x2 = new Rectangle(new Point(GetTabRect(i).Location.X - 2, GetTabRect(i).Location.Y - 2), new Size(GetTabRect(i).Width + 3, GetTabRect(i).Height + 1));
                // G.FillRectangle(New SolidBrush(Color.FromArgb(50, 50, 50)), x2) 'Tab Highlight
                G.DrawLine(new Pen(Color.FromArgb(96, 110, 121)), new Point(x2.Right, x2.Top), new Point(x2.Right, x2.Bottom));
                if (!(ImageList is null))
                {
                    try
                    {
                        if (!(ImageList.Images[TabPages[i].ImageIndex] is null))
                        {
                            G.DrawImage(ImageList.Images[TabPages[i].ImageIndex], new Point(x2.Location.X + 8, x2.Location.Y + 6));
                            G.DrawString("      " + TabPages[i].Text, Font, Brushes.White, new Rectangle(x2.X, x2.Y - 1, x2.Width, x2.Height), new StringFormat() { LineAlignment = StringAlignment.Near, Alignment = StringAlignment.Near });
                        }
                        else
                        {
                            G.DrawString(TabPages[i].Text, FF, new SolidBrush(Color.FromArgb(210, 220, 230)), new Rectangle(x2.X, x2.Y - 1, x2.Width, x2.Height), new StringFormat() { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Center });
                        }
                    }
                    catch
                    {
                        G.DrawString(TabPages[i].Text, FF, new SolidBrush(Color.FromArgb(210, 220, 230)), new Rectangle(x2.X, x2.Y - 1, x2.Width, x2.Height), new StringFormat() { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Center });
                    }
                }
                else
                {
                    G.DrawString(TabPages[i].Text, FF, new SolidBrush(Color.FromArgb(210, 220, 230)), new Rectangle(x2.X, x2.Y - 1, x2.Width, x2.Height), new StringFormat() { LineAlignment = StringAlignment.Center, Alignment = StringAlignment.Center });
                }
            }

            G.FillRectangle(new SolidBrush(Color.FromArgb(50, 50, 50)), new Rectangle(86, -1, Width - 86, Height + 1)); // Page Fill Full
            var c = new Color[] { Color.FromArgb(20, 20, 20), Color.FromArgb(40, 40, 40), Color.FromArgb(45, 45, 45), Color.FromArgb(46, 46, 46), Color.FromArgb(47, 47, 47), Color.FromArgb(48, 48, 48), Color.FromArgb(49, 49, 49), Color.FromArgb(50, 50, 50) };
            Draw.InnerGlowRounded(G, new Rectangle(86, 0, Width - 87, Height - 1), 3, c); // Fill Page
        }

        G.DrawRectangle(new Pen(new SolidBrush(Color.FromArgb(50, 50, 50))), new Rectangle(0, 0, ItemSize.Height + 4, Height - 1)); // Full Tab Outer Outline
        G.DrawRectangle(new Pen(new SolidBrush(Color.FromArgb(20, 20, 20))), new Rectangle(1, 0, ItemSize.Height + 3, Height - 2)); // Full Tab Inner Outline
        e.Graphics.DrawImage(B, 0, 0);
        G.Dispose();
        B.Dispose();
    }
}

[DefaultEvent("CheckedChanged")]
public partial class MephCheckBox : Control
{

    #region  Control Help - MouseState & Flicker Control
    protected override void OnMouseEnter(EventArgs e)
    {
        base.OnMouseEnter(e);
        Invalidate();
    }

    protected override void OnMouseDown(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        Invalidate();
    }

    protected override void OnMouseUp(System.Windows.Forms.MouseEventArgs e)
    {
        base.OnMouseUp(e);
        Invalidate();
    }

    protected override void OnTextChanged(EventArgs e)
    {
        base.OnTextChanged(e);
        Invalidate();
    }

    private bool _Checked;

    public bool Checked
    {
        get
        {
            return _Checked;
        }

        set
        {
            _Checked = value;
            Invalidate();
        }
    }

    private Color _accentColor;

    public Color AccentColor
    {
        get
        {
            return _accentColor;
        }

        set
        {
            _accentColor = value;
            Invalidate();
        }
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        Height = 24;
    }

    protected override void OnClick(EventArgs e)
    {
        _Checked = !_Checked;
        CheckedChanged?.Invoke(this);
        base.OnClick(e);
    }

    public event CheckedChangedEventHandler CheckedChanged;

    public delegate void CheckedChangedEventHandler(object sender);
    #endregion


    public MephCheckBox() : base()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor | ControlStyles.OptimizedDoubleBuffer, true);
        BackColor = Color.Transparent;
        ForeColor = Color.Black;
        Size = new Size(250, 24);
        _accentColor = Color.Maroon;
        DoubleBuffered = true;
    }

    protected override void OnPaint(System.Windows.Forms.PaintEventArgs e)
    {
        var B = new Bitmap(Width, Height);
        Graphics G = Graphics.FromImage(B);
        var radioBtnRectangle = new Rectangle(0, 0, Height - 1, Height - 1);
        var InnerRect = new Rectangle(5, 5, Height - 11, Height - 11);
        G.SmoothingMode = SmoothingMode.HighQuality;
        G.CompositingQuality = CompositingQuality.HighQuality;
        G.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
        G.Clear(BackColor);
        var bgGrad = new LinearGradientBrush(radioBtnRectangle, Color.FromArgb(50, 50, 50), Color.FromArgb(40, 40, 40), (short)90);
        G.FillRectangle(bgGrad, radioBtnRectangle);
        G.DrawRectangle(new Pen(Color.FromArgb(20, 20, 20)), radioBtnRectangle);
        G.DrawRectangle(new Pen(Color.FromArgb(55, 55, 55)), new Rectangle(1, 1, Height - 3, Height - 3));
        if (Checked)
        {
            var fillGradient = new LinearGradientBrush(InnerRect, _accentColor, Color.FromArgb(_accentColor.R, _accentColor.G, _accentColor.B), 90);
            G.FillRectangle(fillGradient, InnerRect);
            G.DrawRectangle(new Pen(Color.FromArgb(25, 25, 25)), InnerRect);
        }

        var drawFont = new Font("Tahoma", 10, FontStyle.Bold);
        Brush nb = new SolidBrush(Color.FromArgb(200, 200, 200));
        G.DrawString(Text, drawFont, nb, new Point(28, 12), new StringFormat() { Alignment = StringAlignment.Near, LineAlignment = StringAlignment.Center });
        e.Graphics.DrawImage(B, 0, 0);
        G.Dispose();
        B.Dispose();
    }
}