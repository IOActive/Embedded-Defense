using System;
using System.IO;

namespace TestDefense.Models
{
    /// <summary>
    /// A stream which keeps an in-memory copy as it passes the bytes through
    /// </summary>
    public class OutputFilterStream : Stream
    {
        private readonly Stream InnerStream;
        private readonly MemoryStream CopyStream;

        public OutputFilterStream(Stream inner)
        {
            this.InnerStream = inner;
            this.CopyStream = new MemoryStream();
        }

        public string ReadStream()
        {
            lock (this.InnerStream)
            {
                if (this.CopyStream.Length <= 0L ||
                    !this.CopyStream.CanRead ||
                    !this.CopyStream.CanSeek)
                {
                    return String.Empty;
                }

                long pos = this.CopyStream.Position;
                this.CopyStream.Position = 0L;
                try
                {
                    return new StreamReader(this.CopyStream).ReadToEnd();
                }
                finally
                {
                    try
                    {
                        this.CopyStream.Position = pos;
                    }
                    catch { }
                }
            }
        }


        public override bool CanRead
        {
            get { return this.InnerStream.CanRead; }
        }

        public override bool CanSeek
        {
            get { return this.InnerStream.CanSeek; }
        }

        public override bool CanWrite
        {
            get { return this.InnerStream.CanWrite; }
        }

        public override void Flush()
        {
            this.InnerStream.Flush();
        }

        public override long Length
        {
            get { return this.InnerStream.Length; }
        }

        public override long Position
        {
            get { return this.InnerStream.Position; }
            set { this.CopyStream.Position = this.InnerStream.Position = value; }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return this.InnerStream.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            this.CopyStream.Seek(offset, origin);
            return this.InnerStream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            this.CopyStream.SetLength(value);
            this.InnerStream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            this.CopyStream.Write(buffer, offset, count);
            this.InnerStream.Write(buffer, offset, count);
        }
    }
}