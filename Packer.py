import sys, getopt, os, glob, pathlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def Encrypt(data):
    # Chứa bytes của các file PE đã được mã hóa
    newfile = b""
    # Tạo 1 key ngẫu nhiên gồm 32 bytes kí tự và lưu key đó vào
    # một file có tên AES.key
    key = get_random_bytes(32)
    with open("AES.key", "wb") as keyfile:
        keyfile.write(key)
    # Tạo thuật toán mã hóa
    cipher_encrypt = AES.new(key, AES.MODE_CFB)
    # Lưu lại iv để sử dụng lại cho việc giải mã file PE
    newfile += cipher_encrypt.iv
    # Đếm số dữ liệu đã được mã hóa
    data_size_encrypted = 0
    # Mã hóa đến hết chuỗi dữ liệu
    while data_size_encrypted < len(data):
        # Mỗi lần mã hóa sẽ mã hóa một chuỗi gồm 65536 bytes
        if len(data) - data_size_encrypted > 65536:
            newfile += cipher_encrypt.encrypt(
                data[data_size_encrypted : data_size_encrypted + 65536]
            )

        else:
            newfile += cipher_encrypt.encrypt(data[data_size_encrypted:])
        data_size_encrypted += 65536
    # Trả về các file FE đã được mã hóa để ghi vào file kết quả
    return newfile


def Decrypt(data, keyfile):
    # Đọc key được chứa trong file .key
    key = b""
    with open(keyfile, "rb") as keyfile:
        key = keyfile.read()
    # Đọc IV được lưu sẵn
    iv = data[:16]
    # Đếm số lượng byte đã được giải mã
    data_size_decrypted = 0
    # Chứa các byte của file PE đã giải mã
    data_decrypted = b""
    # Tạo thuật toán giải mã
    cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)
    # Giải mã đến hết chuỗi đữ liệu
    while data_size_decrypted < len(data):
        # Giống như việc mã hóa, việc giải mã cũng thực hiện trên mỗi
        # 65536 byte đã được mã hóa
        if len(data) - data_size_decrypted > 65536:
            # bỏ đi 16 ký tự của IV
            data_decrypted += cipher_decrypt.decrypt(
                data[data_size_decrypted + 16 : data_size_decrypted + 16 + 65536]
            )
        else:
            data_decrypted += cipher_decrypt.decrypt(data[data_size_decrypted + 16 :])

        data_size_decrypted += 65536
    # Trả về các file PE đã được giải mã
    return data_decrypted


def Unpack(exename, keyname):
    # Đọc dữ liệu của file thực thi
    readfile = open(exename, "rb")
    data = readfile.read()
    # Tìm kiếm nơi lưu dữ thông tin các file PE
    startinfo = data.index(b"index=")
    endinfo = data.index(b"=end", startinfo) + 4
    # Giải mã thông tin từ byte sang string
    infoarray = (data[startinfo + 6 : endinfo - 4]).decode().split(":")
    # Giải mã dữ liệu của các file PE
    data_decrypted = Decrypt(data[endinfo:], keyname)
    endinfo = 0
    for i in range(int(len(infoarray) / 2)):
        # In ra thông tin của các file PE đã được nén lại
        print(
            "File: {name}     size: {size}".format(
                name=infoarray[i * 2], size=infoarray[i * 2 + 1]
            )
        )
        # Tạo thành các file PE mới
        file = open(infoarray[i * 2], "wb")
        # Ghi dữ liệu vào các file PE này
        file.write(data_decrypted[endinfo : endinfo + int(infoarray[i * 2 + 1])])
        # Làm mới lại vị trí bắt đầu của file PE tiếp theo được nén
        endinfo = endinfo + int(infoarray[i * 2 + 1])


def Pack(inputdir, output):
    # Đọc tên file Packer nếu tên file đã được thay đổi thành tên khác
    exename = sys.argv[0].split("\\")[-1]
    # Tạo một biến được sử dụng để lưu thông tin các tập tin PE chứa trong nó
    name = b"index="
    # Nối các file PE trở thành một
    data = b""
    # Tìm các tập tin PE có trong thư mục được chọn
    for file in glob.glob(inputdir + "/*.exe"):
        # Đọc kích thước của file để có thể xác định được vị trí
        # chứa file PE sau khi được unpack
        offset = os.path.getsize(file)
        # Kiệt kê tên và các kích thước của các file
        print(
            "File: {name}     size: {size}".format(
                name=file.split("\\")[-1], size=offset
            )
        )
        # Đọc dữ liệu của các file PE
        readfile = open(file, "rb")
        # Ghi lại tên của file và kích thước của file đó
        name += (file.split("\\")[1] + ":" + str(offset) + ":").encode("utf-8")
        # Đọc dữ liệu của file
        data += readfile.read()
    # Đọc dữ liệu của file này để có thể unpack các file PE
    thisfile = open(exename, "rb")
    # Tạo 1 file mới chứa các file PE đã được pack
    newfile = open(output, "wb")
    newfile.write(
        thisfile.read()
        + name
        + str(os.path.getsize(exename) + 100).encode("utf-8")
        + b"=end"
        + Encrypt(data)
    )


def main(argv):
    inputdir = ""
    outputfile = ""
    try:
        opts, args = getopt.getopt(argv, "i:o:", ["idir=", "ofile="])
    except getopt.GetoptError:
        print("Packer.exe -i <inputdir> -o <outputfile>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print("Packer.exe -i <inputdir> -o <outputfile>")
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputdir = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg
    # Kiểm tra đầu vào đã đúng chưa trước khi thực hiện chương trình
    if (inputdir != "") and (outputfile != ""):
        print("Input directory is: ", inputdir)
        print("Output file is: ", outputfile)
        Pack(inputdir, outputfile)


if __name__ == "__main__":
    exename = sys.argv[0].split("\\")[-1]
    file = open(exename,'rb')
    data = file.read()
    # Kiểm tra xem file này có chứa các file PE được nén hay không
    # Nếu có sẽ tiến hành unpack
    try:
        startinfo = data.index(b"index=")
        endinfo = data.index(b"=end", startinfo) + 4
        originalsize = int((data[startinfo + 6 : endinfo - 4]).decode().split(":")[-1])
        if os.path.getsize(exename) > originalsize:
            Unpack(exename, sys.argv[1])
    # Nếu không sẽ thực thi để pack các file PE
    except:
        main(sys.argv[1:])
    
