import pyshark
import zipfile
import base64

streams = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27]
for stream in streams:
    cap = pyshark.FileCapture('phreaky.pcap', display_filter=f'tcp.stream eq {stream}')
    payload = ''
    while True:
        try:
            p = cap.next()
            #print(p)
        except StopIteration:  # Reached end of capture file.
            break
        try:
            # print data from the selected stream
            payload += bytes.fromhex(p.tcp.payload.replace(':', '')).decode('utf-8')
        except AttributeError:  # Skip the ACKs.
            pass
    if 'Content-ID:' in payload:
        password = None
        attachment = None
        for part in payload.split('\r\n\r\n'):
            if "Password:" in part:
                password = part.split(' ')[-1]
            elif "UEsD" in part:
                attachment = part.replace('\r\n', '')
        print(password, attachment)
        filename = f'attachments/{stream}.zip'
        open(filename, 'wb').write(base64.b64decode(attachment))
        with zipfile.ZipFile(filename) as file:
            file.extractall(path='attachments/', pwd=password.encode('utf-8'))
    cap.close()

pdf = b''
for i in range(len(streams)):
    pdf += open(f'attachments/phreaks_plan.pdf.part{i+1}', 'rb').read()
open('attachments/phreaks_plan.pdf', 'wb').write(pdf)