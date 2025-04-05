# ANALISIS DE ARCHIVO Y LINKS MALICIOSOS CON VIRUS TOTAL #
import os, sys, requests, hashlib, pyfiglet, time
from colorama import Fore, init, Style
init(autoreset=True)

GREEN=f'{Fore.GREEN}{Style.BRIGHT}'
RED=f'{Fore.RED}{Style.BRIGHT}'
WHITE=f'{Fore.WHITE}{Style.BRIGHT}'

api_key = "5ccc5ed7c1decdfc3b81dbf8a844d62ac71bebc348e83806d1898583412b16c7"

def banner():
 banner=pyfiglet.figlet_format(' Ruxer', font="bubble")
 print(f'{GREEN}{banner}{WHITE} [=] CREATOR => {GREEN}[PGX]{WHITE}\n')

def showInfo(res, xy):
 scan1 = res['scans']
 scan2 = res['scans'].keys()
 detectedArray = []
 threats = []
 for i in scan2:
  detected = scan1[i]['detected']
  result = scan1[i]['result']
  if detected == False:
   print(f' {GREEN}[+] {WHITE}[{i}] => {GREEN}{detected},{WHITE} {result if result else "clean file"}')
  else:
   print(f' {GREEN}[+] {WHITE}[{i}] => {GREEN}{detected},{WHITE} {result if result else ""}')
   threats.append(i)
  detectedArray.append(detected)
 true = sum(detectedArray)
 false = len(detectedArray) - true
 print(f'\n{GREEN} [+] Motores de analisis de amenazas:')
 if true == 0:
  if xy == True:
    print(f' [{false}] motores dicen que el link es {GREEN}[SEGURO]{WHITE} ')
  else:
    print(f' [{false}] motores dicen que el fichero es {GREEN}[SEGURO]{WHITE} ')
 else:
  print(f' Se encontraron [{true}] Amenazas {RED}[INSEGURO]{WHITE}')
  print(f' -> {", ".join(threats)}')


def analizeUrl(link):
 detectedArray=[]
 threats=[]
 params = {'apikey': api_key, 'resource': link}
 response = requests.get("https://www.virustotal.com/vtapi/v2/url/report", params=params)
 if response.status_code == 200:
  res=response.json()
  showInfo(res, True)

import time

def analizeFile(filename):
 upload=[]
 while True:
  try:
   with open(filename, "rb") as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()
   params = {'apikey': api_key, 'resource': file_hash}
   res = requests.get("https://www.virustotal.com/vtapi/v2/file/report", params=params).json()
   if not upload:
    if res.get('response_code') != 1:
     print(f"{GREEN}[*] Subiendo archivo a VirusTotal...{WHITE}")
     with open(filename, "rb") as f:
      files = {'file': (os.path.basename(filename), f)}
      requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params={'apikey': api_key})
     print(f"{GREEN}[*] Analizando... (esto puede tomar 2-3 minutos)\n   Debido a las limitaciones de API_KEY\n   Gratuitas, si posees una API_KEY Premium\n   Cambie la que el script tiene por defecto.{WHITE}")
     upload.append(True)
   while True:
    res = requests.get("https://www.virustotal.com/vtapi/v2/file/report", params=params).json()
    if res.get('response_code') == 1:
     showInfo(res, False)
     return
    time.sleep(5)
  except Exception:
   time.sleep(10)
   continue

def conditions(option, y):
 if option == '-u':
  analizeUrl(y)
 elif option == '-f':
  analizeFile(y)
 else:
  print(f' Argumentos invalidos{RED} ...{WHITE}')

### ARGUMENTS ###
argv=sys.argv
script_name=os.path.basename(__file__)
banner()
try:
 x=argv[1]
 y=argv[2]
 conditions(x, y)
except:
 print(f' {GREEN}[*]{WHITE} Faltan argumentos...\n {GREEN}python {script_name} -u [LINK]{WHITE}\n => Analiza un LINK\n\n {GREEN}python {script_name} -f [FILE]\n Ejemplo: python {script_name} -f .\\file (WINDOWS)\n Ejemplo: python {script_name} -f ./file (LINUX){WHITE}\n => Analiza cualquier FICHERO')
# END ARGUMENTS #

