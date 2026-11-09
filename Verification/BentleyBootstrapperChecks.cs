using System.Buffers.Binary;
using System.IO;
using System.Text;
using InstallerAnalyzer.Services;

internal static class BentleyBootstrapperChecks
{
    public static void Run(string root, Action<bool,string> check)
    {
        var dir=Path.Combine(root,"bentley");Directory.CreateDirectory(dir);
        var path=Path.Combine(dir,"inert-resource-fixture.exe");
        byte[] Fixture(params string[] names)
        {
            using var cabinet=new MemoryStream(); using var writer=new BinaryWriter(cabinet,Encoding.UTF8,true);
            writer.Write(new byte[44]);
            foreach(var name in names){writer.Write(1u);writer.Write(0u);writer.Write((ushort)0);writer.Write((ushort)0);writer.Write((ushort)0);writer.Write((ushort)0x20);writer.Write(Encoding.ASCII.GetBytes(name));writer.Write((byte)0);}
            uint data=(uint)cabinet.Position;writer.Write(new byte[9]);var cab=cabinet.ToArray();
            void C32(int offset,uint value)=>BinaryPrimitives.WriteUInt32LittleEndian(cab.AsSpan(offset),value);
            void C16(int offset,ushort value)=>BinaryPrimitives.WriteUInt16LittleEndian(cab.AsSpan(offset),value);
            Encoding.ASCII.GetBytes("MSCF").CopyTo(cab,0);C32(8,(uint)cab.Length);C32(16,44);cab[24]=3;cab[25]=1;C16(26,1);C16(28,(ushort)names.Length);C32(36,data);C16(40,1);
            const int resourceHeader=88;int resourceBytes=resourceHeader+cab.Length;int raw=(resourceBytes+511)/512*512;
            var image=new byte[512+raw];
            void U16(int offset,ushort value)=>BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(offset),value);
            void U32(int offset,uint value)=>BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(offset),value);
            image[0]=(byte)'M';image[1]=(byte)'Z';U32(60,128);image[128]=(byte)'P';image[129]=(byte)'E';U16(132,0x14c);U16(134,1);U16(148,224);U16(150,0x102);
            const int optional=152;U16(optional,0x10b);U32(optional+28,0x400000);U32(optional+32,4096);U32(optional+36,512);U32(optional+56,8192);U32(optional+60,512);U16(optional+68,3);U32(optional+92,16);U32(optional+112,4096);U32(optional+116,(uint)resourceBytes);
            const int section=376;Encoding.ASCII.GetBytes(".rsrc").CopyTo(image,section);U32(section+8,(uint)resourceBytes);U32(section+12,4096);U32(section+16,(uint)raw);U32(section+20,512);U32(section+36,0x40000040);
            const int res=512;U16(res+14,1);U32(res+16,10);U32(res+20,0x80000018);U16(res+24+14,1);U32(res+40,1);U32(res+44,0x80000030);U16(res+48+14,1);U32(res+64,1033);U32(res+68,72);U32(res+72,4096+resourceHeader);U32(res+76,(uint)cab.Length);cab.CopyTo(image,res+resourceHeader);
            return image;
        }
        var good=Fixture("Product.msi","Settings.ini","PrereqInst32.exe","dotnetfx35setup.exe");File.WriteAllBytes(path,good);
        var evidence=BentleyBootstrapperService.Inspect(path,"Bentley Systems, Inc.");
        check(evidence is not null && evidence.Files.Count==4 && evidence.Files.Any(f=>f.Name=="Product.msi"),"Bentley identification reads structured CAB resource entries without extracting or running payloads");
        check(BentleyBootstrapperService.Inspect(path,"Unrelated publisher") is null,"Bentley CAB layout does not identify an unrelated vendor");
        foreach(var names in new[]{new[]{"Settings.ini","PrereqInst32.exe","readme.txt"},new[]{"Product.msi","Settings.ini","other.exe"},new[]{"Product.msi","other.ini","PrereqInst32.exe"},new[]{"Product.msi","Settings.ini","PrereqInst32.exe","../escape.exe"},new[]{"Product.msi","Settings.ini","PrereqInst32.exe","Settings.ini"}})
        {File.WriteAllBytes(path,Fixture(names));check(BentleyBootstrapperService.Inspect(path,"Bentley Systems, Inc.") is null,"Bentley rejects incomplete or unsafe CAB layout: "+string.Join(",",names));}
        foreach(var mutation in new[]{"size","offset","span","count","data"})
        {
            var bytes=(byte[])good.Clone();const int cab=600;
            if(mutation=="size")BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(cab+8),uint.MaxValue);
            if(mutation=="offset")BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(cab+16),uint.MaxValue);
            if(mutation=="span")BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(cab+30),1);
            if(mutation=="count")BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(cab+28),ushort.MaxValue);
            if(mutation=="data")BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(cab+36),44);
            File.WriteAllBytes(path,bytes);check(BentleyBootstrapperService.Inspect(path,"Bentley Systems, Inc.") is null,"Bentley rejects malformed CAB "+mutation);
        }
        File.WriteAllText(path,"Bentley Systems Settings.ini PrereqInst32.exe Product.msi MSCF");
        check(BentleyBootstrapperService.Inspect(path,"Bentley Systems, Inc.") is null,"Loose Bentley names do not replace PE/CAB structure evidence");
    }
}
