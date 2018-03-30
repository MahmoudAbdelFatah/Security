using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {

        private int keyScheduleSize = 11;
        private BMatrix[] mKeySchedule;

    

        public override string Decrypt(string cipherText, string key)
        {
            //https://stackoverflow.com/questions/3436822/aes-decryption-algorithm

            cipherText = cipherText.Replace("0x", "");
            key = key.Replace("0x", "");
            if (cipherText.Length != 32 || key.Length != 32)
                return "Only 128-bit keys.";

            BMatrix keyMat = new BMatrix(4, 4, key);
            BuildKeySchedule(keyMat, false);

            BMatrix CTMat = new BMatrix(4, 4, cipherText);
            CTMat.AddRoundKey(mKeySchedule[keyScheduleSize - 1]);
            CTMat.InvShiftRows();
            CTMat.InvSubBytes();


            for (int i = keyScheduleSize - 2; i >= 1; i--)
            {
                CTMat.AddRoundKey(mKeySchedule[i]);
                CTMat.InvMixCols();
                CTMat.InvShiftRows();
                CTMat.InvSubBytes();
            }


            CTMat.AddRoundKey(mKeySchedule[0]);
            return "0x" + CTMat.ToPlainTxt();
        }
       
        public override string Encrypt(string plainText, string key)
        {
            plainText = plainText.Replace("0x", "");
            key = key.Replace("0x", "");
            //if (plainText.Length != 32 || key.Length != 32)
            //    return "Only 128-bit keys.";

            BMatrix keyMat = new BMatrix(4, 4, key);
            BuildKeySchedule(keyMat, false);

            BMatrix PTMat = new BMatrix(4, 4, plainText);
            //Add Round Key
            PTMat.AddRoundKey(keyMat);
            for (int i = 0; i < keyScheduleSize - 2; i++)
            {
                PTMat.SubBytes();
                PTMat.ShiftRows();
                PTMat.MixCols();
                PTMat.AddRoundKey(mKeySchedule[i + 1]);
            }
            PTMat.SubBytes();
            PTMat.ShiftRows();
            PTMat.AddRoundKey(mKeySchedule[keyScheduleSize - 1]);


            return "0x"+PTMat.ToPlainTxt();
        }

        void BuildKeySchedule(BMatrix SeedKey, bool printKeys)
        {
            mKeySchedule = new BMatrix[keyScheduleSize];
            mKeySchedule[0] = new BMatrix(SeedKey);
            //if (printKeys)
            //Console.WriteLine("cipher Key\n" + mKeySchedule[0].ToString());

            for (int i = 1; i < keyScheduleSize; i++)
            {
                mKeySchedule[i] = mKeySchedule[i - 1].GetNextKey(i - 1);
                //if (printKeys)
                //    Console.WriteLine("Round Key " + i + "\n" + mKeySchedule[i].ToString());

            }
        }






        class BMatrix
        {
            public int rows, cols;
            private byte[][] mat;
            public BMatrix GetNextKey(int RconIndex)
            {
                BMatrix nextKey = new BMatrix(rows, cols);

                for (int i = 0; i < cols; i++)
                {
                    if (i == 0)
                    {
                        nextKey.SetCol(0, ShiftColUp(3, 1, false));
                        nextKey.SetCol(0, SubBytes(nextKey.GetCol(0)));
                        nextKey.SetCol(0, XOR(nextKey.GetCol(0), new byte[] { Rcon[RconIndex], 0, 0, 0 }));
                        nextKey.SetCol(0, XOR(nextKey.GetCol(0), GetCol(0)));
                    }
                    else
                    {
                        nextKey.SetCol(i, XOR(nextKey.GetCol(i - 1), GetCol(i)));
                    }

                }
                return nextKey;
            }

            static byte[] Rcon = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
            public byte[] XOR(byte[] arr1, byte[] arr2)
            {
                byte[] arr = new byte[arr1.Length];
                for (int i = 0; i < arr1.Length; i++)
                    arr[i] = (byte)(arr1[i] ^ arr2[i]);
                return arr;
            }

            private byte[] ShiftColUp(int colIndex, int shiftCnt, bool SetInMat)
            {
                //checked
                //conside row =  [27 bf b4 41]
                // ShiftRow(rowIndex , 1)
                //        row =  [bf b4 41 27]
                byte[] nCol = new byte[rows];
                int c = 0;
                for (int i = shiftCnt; i < rows; i++)
                {
                    nCol[c] = mat[i][colIndex];
                    c++;
                }
                for (int i = 0; i < shiftCnt; i++)
                {
                    nCol[c] = mat[i][colIndex];
                    c++;
                }
                if (SetInMat)
                    for (int i = 0; i < rows; i++)
                        mat[i][colIndex] = nCol[i];

                return nCol;
            }

            private byte[] ShiftColDwn(int colIndex, int shiftCnt, bool SetInMat)
            {
                //checked
                //conside row =  [27 bf b4 41]
                // ShiftRow(rowIndex , 1)
                //        row =  [bf b4 41 27]
                byte[] nCol = new byte[rows];
                int c = 0;
                for (int i = rows - shiftCnt; i < rows; i++)
                {
                    nCol[c] = mat[i][colIndex];
                    c++;
                }
                for (int i = 0; i < rows - shiftCnt; i++)
                {
                    nCol[c] = mat[i][colIndex];
                    c++;
                }
                if (SetInMat)
                    for (int i = 0; i < rows; i++)
                        mat[i][colIndex] = nCol[i];

                return nCol;
            }
            public override string ToString()
            {
                //checked
                string matStr = "";
                for (int i = 0; i < rows; i++)
                {
                    string rowHex = "{ \"" + BitConverter.ToString(mat[i]).Replace("-", "\",\"") + "\" }, " + "\n";
                    matStr += rowHex;
                }
                return matStr;
            }


            public string ToPlainTxt()
            {
                //checked
                string matStr = "";
                for (int i = 0; i < cols; i++)
                {
                    for (int k = 0; k < rows; k++)
                    {
                        string rowHex = BitConverter.ToString(new byte[] { mat[k][i] }).Replace("-", "");
                        matStr += rowHex;
                    }

                }
                return matStr;
            }
            public void AddRoundKey(BMatrix key)
            {
                //checked
                //if (rows != key.rows || cols != key.rows)
                //    return;

                for (int i = 0; i < rows; i++)
                    for (int k = 0; k < cols; k++)
                    {
                        mat[i][k] = (byte)(mat[i][k] ^ key.mat[i][k]);
                    }
            }

            //SubBytes
            public void SubBytes()
            {
                //checked
                for (int i = 0; i < rows; i++)
                    for (int k = 0; k < cols; k++)
                    {
                        ////Console.Write(BitConverter.ToString( new byte[]{mat[i][k]}).Replace("-", ""));
                        mat[i][k] = Sbox[(mat[i][k] >> 4), (mat[i][k] & 0x0f)];
                        ////Console.Write(" = "+BitConverter.ToString(new byte[] { mat[i][k] }).Replace("-", "")+ "\n");

                    }
            }
            private byte[] SubBytes(byte[] arr)
            {
                byte[] nArr = new byte[arr.Length];
                //checked
                for (int i = 0; i < arr.Length; i++)
                    nArr[i] = Sbox[(arr[i] >> 4), (arr[i] & 0x0f)];
                return nArr;
            }
            private byte[] SubBytesCol(int colIndex, bool SetInMat)
            {

                byte[] NCol = new byte[rows];
                for (int i = 0; i < rows; i++)
                    NCol[i] = Sbox[(mat[i][colIndex] >> 4), (mat[i][colIndex] & 0x0f)];
                if (SetInMat)
                    for (int i = 0; i < rows; i++)
                        mat[i][colIndex] = NCol[i];

                return NCol;

            }
            public void InvSubBytes()
            {
                //checked
                for (int i = 0; i < rows; i++)
                    for (int k = 0; k < cols; k++)
                    {
                        ////Console.Write(BitConverter.ToString( new byte[]{mat[i][k]}).Replace("-", ""));
                        mat[i][k] = ISbox[(mat[i][k] >> 4), (mat[i][k] & 0x0f)];
                        ////Console.Write(" = "+BitConverter.ToString(new byte[] { mat[i][k] }).Replace("-", "")+ "\n");

                    }
            }
            private byte[] InvSubBytes(byte[] arr)
            {
                byte[] nArr = new byte[arr.Length];
                //checked
                for (int i = 0; i < arr.Length; i++)
                    nArr[i] = ISbox[(arr[i] >> 4), (arr[i] & 0x0f)];
                return nArr;
            }
            private byte[] InvSubBytesCol(int colIndex, bool SetInMat)
            {

                byte[] NCol = new byte[rows];
                for (int i = 0; i < rows; i++)
                    NCol[i] = ISbox[(mat[i][colIndex] >> 4), (mat[i][colIndex] & 0x0f)];
                if (SetInMat)
                    for (int i = 0; i < rows; i++)
                        mat[i][colIndex] = NCol[i];

                return NCol;

            }
            ///////////////////////////////////////////////////////////////////////////////////////////////////


            //MixCols
            public void MixCols()
            {
                //checked
                if (cols != 4 || rows != 4)
                    return;

                for (int k = 0; k < cols; k++)
                {
                    SetCol(k, MixCol_Aux(GetCol(k)));
                }
            }
            private byte[] MixCol_Aux(byte[] col)
            {
                //checked
                byte[] NCol = new byte[col.Length];

                NCol[0] = (byte)(
                      MixCol_Aux_cellByCell(col[0], 2)
                    ^ MixCol_Aux_cellByCell(col[1], 3)
                    ^ MixCol_Aux_cellByCell(col[2], 1)
                    ^ MixCol_Aux_cellByCell(col[3], 1));

                NCol[1] = (byte)(
                      MixCol_Aux_cellByCell(col[0], 1)
                    ^ MixCol_Aux_cellByCell(col[1], 2)
                    ^ MixCol_Aux_cellByCell(col[2], 3)
                    ^ MixCol_Aux_cellByCell(col[3], 1));

                NCol[2] = (byte)(
                     MixCol_Aux_cellByCell(col[0], 1)
                   ^ MixCol_Aux_cellByCell(col[1], 1)
                   ^ MixCol_Aux_cellByCell(col[2], 2)
                   ^ MixCol_Aux_cellByCell(col[3], 3));
                NCol[3] = (byte)(
                     MixCol_Aux_cellByCell(col[0], 3)
                   ^ MixCol_Aux_cellByCell(col[1], 1)
                   ^ MixCol_Aux_cellByCell(col[2], 1)
                   ^ MixCol_Aux_cellByCell(col[3], 2));

                return NCol;
            }
            private static byte MixCol_Aux_cellByCell(byte b, int i)
            {
                //checked
                //http://shodhganga.inflibnet.ac.in/bitstream/10603/148501/14/14_chapter%205.pdf

                //one byte cell and mult it by 1 or 2 or 3 
                int _1b = 27; //1b in hex
                switch (i)
                {
                    case 1:
                        return b;
                    case 2:
                        if ((b & (1 << 7)) != 0)
                        {
                            //the left most bit is = 1
                            b = (byte)(b << 1);
                            b = (byte)(b ^ (_1b));
                        }
                        else
                        {
                            //the left most bit is = 0
                            b = (byte)(b << 1);
                        }
                        return b;
                    case 3:
                        return (byte)(MixCol_Aux_cellByCell(b, 2) ^ MixCol_Aux_cellByCell(b, 1));
                    case 9:
                        return (byte)((int)MixCol_Aux_cellByCell(MixCol_Aux_cellByCell(MixCol_Aux_cellByCell(b, 2), 2), 2) ^
                                       (int)b);
                    case 11: //0b
                        return (byte)((int)MixCol_Aux_cellByCell(MixCol_Aux_cellByCell(MixCol_Aux_cellByCell(b, 2), 2), 2) ^
                                      (int)MixCol_Aux_cellByCell(b, 2) ^
                                      (int)b);
                    case 13: //0d
                        return (byte)((int)MixCol_Aux_cellByCell(MixCol_Aux_cellByCell(MixCol_Aux_cellByCell(b, 2), 2), 2) ^
                                    (int)MixCol_Aux_cellByCell(MixCol_Aux_cellByCell(b, 2), 2) ^
                                    (int)b);
                    case 14: //0e
                        return (byte)((int)MixCol_Aux_cellByCell(MixCol_Aux_cellByCell(MixCol_Aux_cellByCell(b, 2), 2), 2) ^
                                    (int)MixCol_Aux_cellByCell(MixCol_Aux_cellByCell(b, 2), 2) ^
                                    (int)MixCol_Aux_cellByCell(b, 2));


                    default:
                        return 0;
                }
            }

            public void InvMixCols()
            {
                //checked
                if (cols != 4 || rows != 4)
                    return;

                for (int k = 0; k < cols; k++)
                {
                    SetCol(k, InvMixCol_Aux(GetCol(k)));
                }
            }
            private byte[] InvMixCol_Aux(byte[] col)
            {
                //checked
                byte[] NCol = new byte[col.Length];

                NCol[0] = (byte)(
                      MixCol_Aux_cellByCell(col[0], 14)
                    ^ MixCol_Aux_cellByCell(col[1], 11)
                    ^ MixCol_Aux_cellByCell(col[2], 13)
                    ^ MixCol_Aux_cellByCell(col[3], 9));

                NCol[1] = (byte)(
                      MixCol_Aux_cellByCell(col[0], 9)
                    ^ MixCol_Aux_cellByCell(col[1], 14)
                    ^ MixCol_Aux_cellByCell(col[2], 11)
                    ^ MixCol_Aux_cellByCell(col[3], 13));

                NCol[2] = (byte)(
                     MixCol_Aux_cellByCell(col[0], 13)
                   ^ MixCol_Aux_cellByCell(col[1], 9)
                   ^ MixCol_Aux_cellByCell(col[2], 14)
                   ^ MixCol_Aux_cellByCell(col[3], 11));
                NCol[3] = (byte)(
                     MixCol_Aux_cellByCell(col[0], 11)
                   ^ MixCol_Aux_cellByCell(col[1], 13)
                   ^ MixCol_Aux_cellByCell(col[2], 9)
                   ^ MixCol_Aux_cellByCell(col[3], 14));

                return NCol;
            }
            ///////////////////////////////////////////////////////////////////////////////////////////////////


            //ShiftRow
            public void ShiftRows()
            {
                for (int i = 1; i < rows; i++)
                {
                    ShiftRowLeft(i, i, true);
                }
            }
            private byte[] ShiftRowLeft(int rowIndex, int shiftCnt, bool SetInMat)
            {
                //checked
                //conside row =  [27 bf b4 41]
                // ShiftRow(rowIndex , 1)
                //        row =  [bf b4 41 27]
                byte[] nRow = new byte[cols];
                int c = 0;
                for (int i = shiftCnt; i < cols; i++)
                {
                    nRow[c] = mat[rowIndex][i];
                    c++;
                }
                for (int i = 0; i < shiftCnt; i++)
                {
                    nRow[c] = mat[rowIndex][i];
                    c++;
                }
                if (SetInMat)
                    for (int i = 0; i < cols; i++)
                        mat[rowIndex][i] = nRow[i];

                return nRow;
            }
            public void InvShiftRows()
            {
                for (int i = 1; i < rows; i++)
                {
                    ShiftRowRight(i, i, true);
                }
            }
            private byte[] ShiftRowRight(int rowIndex, int shiftCnt, bool SetInMat)
            {
                //checked
                //conside row =  [27 bf b4 41] 
                // 0 1 2 3
                // 3 0 1 2
                // 2 3 0 1
                // 1 2 3 0

                // ShiftRow(rowIndex , 1)
                //        row =  [bf b4 41 27]

                byte[] nRow = new byte[cols];
                int c = 0;
                for (int i = cols - shiftCnt; i < cols; i++)
                {
                    nRow[c] = mat[rowIndex][i];
                    c++;
                }
                for (int i = 0; i < cols - shiftCnt; i++)
                {
                    nRow[c] = mat[rowIndex][i];
                    c++;
                }
                if (SetInMat)
                    for (int i = 0; i < cols; i++)
                        mat[rowIndex][i] = nRow[i];

                return nRow;
            }
            /// ///////////////////////////////////////////////////////////////////////////////////////////////////


            public BMatrix(BMatrix bmat)
            {
                this.rows = bmat.rows;
                this.cols = bmat.cols;
                mat = bmat.mat;
            }

            public BMatrix(int rows, int cols)
            {
                this.rows = rows;
                this.cols = cols;
                mat = new byte[rows][];
                for (int i = 0; i < cols; i++)
                    mat[i] = new byte[cols];
            }
            public BMatrix(int rows, int cols, byte[][] mat)
                : this(rows, cols)
            {

                this.mat = mat;
            }
            public BMatrix(int rows, int cols, byte[,] mat)
                : this(rows, cols)
            {
                //checked
                for (int i = 0; i < rows; i++)
                    for (int k = 0; k < cols; k++)
                    {
                        this.mat[i][k] = mat[i, k];
                    }
            }
            public BMatrix(int rows, int cols, string hex)
                : this(rows, cols)
            {
                //checked
                byte[] hexArr = Enumerable.Range(0, hex.Length)
                                 .Where(x => x % 2 == 0)
                                 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                                 .ToArray();
                int c = 0;
                for (int k = 0; k < cols; k++)
                    for (int i = 0; i < rows; i++)
                    {
                        mat[i][k] = hexArr[c];
                        c++;
                    }
            }
            public byte[] GetRow(int rowIndex)
            {
                byte[] row = new byte[cols];
                for (int i = 0; i < cols; i++)
                    row[i] = mat[rowIndex][i];
                return row;
            }
            public byte[] GetCol(int colIndex)
            {
                byte[] col = new byte[rows];
                for (int i = 0; i < rows; i++)
                    col[i] = mat[i][colIndex];
                return col;
            }
            public void SetRow(int rowIndex, byte[] Nrow)
            {
                for (int i = 0; i < cols; i++)
                    mat[rowIndex][i] = Nrow[i];
            }
            public void SetCol(int colIndex, byte[] Ncol)
            {
                for (int i = 0; i < rows; i++)
                    mat[i][colIndex] = Ncol[i];
            }
            public byte GetCell(int row, int col)
            {
                return mat[row][col];
            }
            public void SetCell(int row, int col, byte Nval)
            {
                mat[row][col] = Nval;
            }

            //static int[][] MIxColMat = {
            //    new int[]{2,3,1,1},
            //    new int[]{1,2,3,1},
            //    new int[]{1,1,2,3},
            //    new int[]{3,1,1,2}
            //};
            static byte[,] Sbox = new byte[16, 16] { 
           /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
    /*0*/  {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    /*1*/  {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    /*2*/  {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    /*3*/  {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    /*4*/  {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    /*5*/  {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    /*6*/  {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    /*7*/  {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    /*8*/  {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    /*9*/  {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    /*a*/  {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    /*b*/  {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    /*c*/  {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    /*d*/  {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    /*e*/  {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    /*f*/  {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };


            static byte[,] ISbox = new byte[16, 16] { 
           /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
    /*0*/  {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    /*1*/  {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    /*2*/  {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    /*3*/  {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    /*4*/  {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    /*5*/  {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    /*6*/  {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    /*7*/  {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    /*8*/  {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    /*9*/  {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    /*a*/  {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    /*b*/  {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    /*c*/  {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    /*d*/  {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    /*e*/  {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    /*f*/  {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D},
            };

        }
    }
}
