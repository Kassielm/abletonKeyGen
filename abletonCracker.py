import json
import re
import os
import platform
import sys
import ctypes
import subprocess
import argparse
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA1

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Dummy:
        RESET = RED = WHITE = GREEN = LIGHTBLACK_EX = BRIGHT = ''
    Fore = Style = Dummy()

patcher_version = "v3.0.0"

RED = Fore.RED + Style.BRIGHT
WHITE = Fore.WHITE + Style.BRIGHT
GREY = Fore.LIGHTBLACK_EX + Style.NORMAL
GREEN = Fore.GREEN + Style.BRIGHT
YELLOW = Fore.YELLOW + Style.BRIGHT
PURPLE = Fore.MAGENTA + Style.BRIGHT
RESET = Style.RESET_ALL

os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def run_as_admin(undo=False):
    script = os.path.abspath(sys.argv[0])
    params = sys.argv[1:]
    if undo and "--undo" not in params:
        params.append("--undo")
    params = subprocess.list2cmdline(params)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
    sys.exit(0)

def load_config(filename: str, args):
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        
        # Usa argumentos da linha de comando, se fornecidos; caso contrario usa o arquivo de config
        file_path = args.file_path if args.file_path else data.get("file_path")
        old_signkey = args.old_signkey if args.old_signkey else data.get("old_signkey")
        new_signkey = args.new_signkey if args.new_signkey else data.get("new_signkey")
        hwid = args.hwid if args.hwid else data.get('hwid', '').upper()
        edition = args.edition if args.edition else data.get('edition', 'Suite')
        version = args.version if args.version else data.get('version', 12)
        authorize_file_output = args.authorize_file_output if args.authorize_file_output else data.get('authorize_file_output', 'output/Authorize.auz')
        dsa_params = data.get('dsa_parameters')  # Mantem os parametros DSA apenas na configuracao
        
        if args.undo:
            # Para desfazer, inverte as signkeys
            old_signkey, new_signkey = new_signkey, old_signkey
            
        if not file_path or not old_signkey or not new_signkey:
            raise ValueError("JSON file must contain 'file_path', 'old_signkey', and 'new_signkey'.")
        
        if len(hwid) == 24:
            hwid = "-".join(hwid[i:i+4] for i in range(0, 24, 4))
        assert re.fullmatch(r"([0-9A-F]{4}-){5}[0-9A-F]{4}", hwid), f"Expected hardware ID like 1111-1111-1111-1111-1111-1111, not {hwid}"
        
        if not dsa_params and not args.undo:
            raise ValueError("DSA parameters are missing in the config file.")
            
        return file_path, old_signkey, new_signkey, hwid, edition, version, authorize_file_output, dsa_params
    except FileNotFoundError:
        print(RED + f"O arquivo JSON {filename} nao foi encontrado." + RESET)
        raise
    except json.JSONDecodeError:
        print(RED + f"Erro ao analisar o arquivo JSON {filename}." + RESET)
        raise

def construct_key(dsa_params) -> dsa.DSAPrivateKey:
    p = int(dsa_params['p'], 16)
    q = int(dsa_params['q'], 16)
    g = int(dsa_params['g'], 16)
    y = int(dsa_params['y'], 16)
    x = int(dsa_params['x'], 16)
    params = dsa.DSAParameterNumbers(p, q, g)
    pub = dsa.DSAPublicNumbers(y, params)
    priv = dsa.DSAPrivateNumbers(x, pub)
    return priv.private_key(backend=default_backend())

def replace_signkey_in_file(file_path, old_signkey, new_signkey, undo: bool = False):
    if len(old_signkey) != len(new_signkey):
        raise ValueError("The new signkey must be the same length as the old signkey.")
    if old_signkey.startswith("0x"):
        old_signkey = old_signkey[2:]
    if new_signkey.startswith("0x"):
        new_signkey = new_signkey[2:]
    if not re.fullmatch(r'[0-9a-fA-F]+', old_signkey):
        raise ValueError("The old signkey is not valid.")
    if not re.fullmatch(r'[0-9a-fA-F]+', new_signkey):
        raise ValueError("The new signkey is not valid.")
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
        old_signkey_bytes = bytes.fromhex(old_signkey)
        new_signkey_bytes = bytes.fromhex(new_signkey)
        
        if old_signkey_bytes not in content:
            if undo:
                print(RED + f"A signkey antiga nao foi encontrada no arquivo." + RESET)
            else:
                if new_signkey_bytes in content:
                    print(YELLOW + "A nova signkey ja esta presente no arquivo. O Ableton ja esta patchado." + RESET)
                else:
                    print(RED + "Nem a signkey antiga nem a nova foram encontradas no arquivo. Voce pode estar usando uma versao nao suportada ou um patch diferente." + RESET)
        else:
            if undo:
                print(WHITE + f"A signkey antiga foi encontrada. Substituindo..." + RESET)
            else:
                print(WHITE + "A signkey antiga foi encontrada. Substituindo..." + RESET)
                
            content = content.replace(old_signkey_bytes, new_signkey_bytes)
            with open(file_path, 'wb') as file:
                file.write(content)
                
            if old_signkey_bytes in content:
                print(RED + "Erro: A signkey antiga ainda esta presente no arquivo." + RESET)
            else:
                print(GREEN + "Signkey substituida com sucesso." + RESET)
    except PermissionError:
        print(RED + "\nPermissao negada! Tente executar o script como Administrador." + RESET)
        if platform.system() == "Windows":
            print(GREY + "Reabrindo com privilegios de administrador..." + RESET)
            run_as_admin(undo)
        else:
            print(GREY + "No Linux/macOS, tente executar com sudo." + RESET)
        raise
    except FileNotFoundError:
        print(RED + f"O arquivo '{file_path}' nao foi encontrado." + RESET)
        raise
    except Exception as e:
        print(RED + f"Ocorreu um erro: {e}" + RESET)
        raise

def sign(k: dsa.DSAPrivateKey, m: str) -> str:
    assert k.key_size == 1024
    sig = k.sign(m.encode(), SHA1())
    r, s = decode_dss_signature(sig)
    return "{:040X}{:040X}".format(r, s)

def fix_group_checksum(group_number: int, n: int) -> int:
    checksum = n >> 4 & 0xf ^ \
    n >> 5 & 0x8 ^ \
    n >> 9 & 0x7 ^ \
    n >> 11 & 0xe ^ \
    n >> 15 & 0x1 ^ \
    group_number
    return n & 0xfff0 | checksum

def overall_checksum(groups: list[int]) -> int:
    r = 0
    for i in range(20):
        g, digit = divmod(i, 4)
        v = groups[g] >> (digit * 8) & 0xff
        r ^= v << 8
        for _ in range(8):
            r <<= 1
            if r & 0x10000:
                r ^= 0x8005
    return r & 0xffff

def random_serial():
    """ 3xxc-xxxc-xxxc-xxxc-xxxc-dddd, onde x e aleatorio, c e checksum de cada grupo e d e checksum de todos os grupos """
    groups = [randint(0x3000, 0x3fff), randint(0x0000, 0xffff), randint(0x0000, 0xffff), randint(0x0000, 0xffff), randint(0x0000, 0xffff)]
    for i in range(5):
        groups[i] = fix_group_checksum(i, groups[i])
    d = overall_checksum(groups)
    return "{:04X}-{:04X}-{:04X}-{:04X}-{:04X}-{:04X}".format(*groups, d)

def generate_single(k: dsa.DSAPrivateKey, id1: int, id2: int, hwid: str) -> str:
    f = "{},{:02X},{:02X},Standard,{}"
    serial = random_serial()
    msg = f.format(serial, id1, id2, hwid)
    sig = sign(k, msg)
    return f.format(serial, id1, id2, sig)

def generate_all(k: dsa.DSAPrivateKey, edition: str, version: int, hwid: str) -> str:
    yield generate_single(k, EDITIONS[edition], version << 4, hwid)
    for i in range(0x40, 0xff + 1):
        yield generate_single(k, i, 0x10, hwid)
    for i in range(0x8000, 0x80ff + 1):
        yield generate_single(k, i, 0x10, hwid)

EDITIONS = {
    "Lite": 4,
    "Intro": 3,
    "Standard": 0,
    "Suite": 2,
}

def get_user_config_dir():
    system = platform.system()
    if system == "Windows":
        return os.getenv('APPDATA')
    elif system == "Darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        return os.getenv('XDG_CONFIG_HOME', os.path.join(os.path.expanduser("~"), ".config"))

def find_installations():
    system = platform.system()
    installations = []
    if system == "Windows":
        base_dir = "C:\\ProgramData\\Ableton"
        if not os.path.exists(base_dir):
            return installations
        for entry in os.listdir(base_dir):
            if entry.startswith('.'):
                continue
            if "Live" in entry:
                entry_path = os.path.join(base_dir, entry)
                if os.path.isdir(entry_path):
                    program_dir = os.path.join(entry_path, "Program")
                    if os.path.exists(program_dir):
                        for file in os.listdir(program_dir):
                            if file.endswith(".exe") and "Live" in file:
                                exe_path = os.path.join(program_dir, file)
                                installations.append((exe_path, entry))
    elif system == "Darwin":
        base_dir = "/Applications"
        if not os.path.exists(base_dir):
            return installations
        for entry in os.listdir(base_dir):
            if entry.startswith('.'):
                continue
            if entry.endswith(".app") and "Ableton Live" in entry:
                app_path = os.path.join(base_dir, entry)
                exe_path = os.path.join(app_path, "Contents", "MacOS", "Live")
                if os.path.exists(exe_path):
                    name = entry.replace(".app", "")
                    installations.append((exe_path, name))

    installations.reverse()
    return installations

def find_installation_data():
    config_dir = get_user_config_dir()
    base_dir = os.path.join(config_dir, "Ableton")
    data_dirs = []
    if not os.path.exists(base_dir):
        return data_dirs
    for entry in os.listdir(base_dir):
        if entry.startswith('.'):  # Ignora pastas que comecam com .
            continue
        entry_path = os.path.join(base_dir, entry)
        if os.path.isdir(entry_path) and "Live" in entry:
            data_dirs.append((entry_path, entry))
    
    # Inverte a lista para que as versoes mais novas fiquem no topo
    data_dirs.reverse()
    return data_dirs

def open_folder(path):
    folder_path = os.path.dirname(path)
    if not os.path.exists(folder_path):
        print(RED + f"A pasta nao existe: {folder_path}" + RESET)
        return False
        
    try:
        if platform.system() == "Windows":
            os.startfile(folder_path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", folder_path])
        else:  # Linux e outros sistemas Unix-like
            subprocess.Popen(["xdg-open", folder_path])
        return True
    except Exception as e:
        print(RED + f"Falha ao abrir pasta: {e}" + RESET)
        return False

def main():
    # Configura o parser de argumentos da linha de comando
    parser = argparse.ArgumentParser(description='Ableton Live Patcher', add_help=False)
    parser.add_argument('--undo', action='store_true', help='Revert the patch (swap signkeys and skip authorization file)')
    parser.add_argument('--file_path', type=str, help='Path to Ableton Live executable (or "auto")')
    parser.add_argument('--old_signkey', type=str, help='Old signkey (hex string)')
    parser.add_argument('--new_signkey', type=str, help='New signkey (hex string)')
    parser.add_argument('--hwid', type=str, help='Hardware ID (24 hex chars or 6 groups of 4)')
    parser.add_argument('--edition', type=str, choices=['Lite', 'Intro', 'Standard', 'Suite'], help='Ableton edition')
    parser.add_argument('--version', type=int, help='Ableton version (e.g., 12)')
    parser.add_argument('--authorize_file_output', type=str, help='Output path for Authorize.auz (or "auto")')
    parser.add_argument('--help', action='store_true', help='Show this help message')
    parser.add_argument('--config_file', type=str, default='config.json', help='Path to config JSON file (default: config.json)'
)
    
    # Processa os argumentos
    args, unknown = parser.parse_known_args()
    
    # Mostra ajuda se solicitado
    if args.help:
        print(WHITE + "Ableton Live Patcher " + RED + patcher_version + RESET)
        print(WHITE + "Uso: python patcher.py [OPCOES]" + RESET)
        print("\nOpcoes:")
        print("  --undo                      Reverte o patch (troca as signkeys e pula o arquivo de autorizacao)")
        print("  --file_path PATH            Caminho para o executavel do Ableton Live ou 'auto'")
        print("  --old_signkey HEX           Signkey antiga (string hex)")
        print("  --new_signkey HEX           Nova signkey (string hex)")
        print("  --hwid ID                   ID de hardware (24 caracteres hex ou 6 grupos de 4)")
        print("  --edition EDITION           Edicao do Ableton (Lite, Intro, Standard, Suite)")
        print("  --version NUMBER            Versao do Ableton (ex.: 12)")
        print("  --authorize_file_output PATH Caminho de saida para Authorize.auz ou 'auto'")
        print("  --help                      Mostra esta mensagem de ajuda")
        print("\n" + YELLOW + "Nota: argumentos de linha de comando sobrescrevem os valores em config.json" + RESET)
        return

    if platform.system() == "Windows" and not is_admin():
        print(RED + "\nEsta operacao requer privilegios de administrador no Windows." + RESET)
        print(GREY + "Reabrindo com direitos de administrador..." + RESET)
        run_as_admin(args.undo)
        return

    print(RED + r"""      ___.   .__          __                _________                       __                 
_____ \_ |__ |  |   _____/  |_  ____   ____ \_   ___ \____________    ____ |  | __ ___________ 
\__  \ | __ \|  | _/ __ \   __\/  _ \ /    \/    \  \/\_  __ \__  \ _/ ___\|  |/ // __ \_  __ \
 / __ \| \_\ \  |_\  ___/|  | (  <_> )   |  \     \____|  | \// __ \\  \___|    <\  ___/|  | \/
(____  /___  /____/\___  >__|  \____/|___|  /\______  /|__|  (____  /\___  >__|_ \\___  >__|   
     \/    \/          \/                 \/        \/            \/     \/     \/    \/    
   """ + RESET)
    print(WHITE + "Feito por " + RED + "Kassielm" + RESET)
    print(WHITE + "Versao: " + RED + patcher_version + RESET)
    print(WHITE + "GitHub: " + GREY + "https://github.com/kassielm/abletonKeyGen" + RESET + "\n")
    
    if args.undo:
        print(PURPLE + "MODO UNDO: Revertendo patch e pulando geracao do arquivo de autorizacao." + RESET)

    print(YELLOW + "NOTA: Certifique-se de que o Ableton Live nao esteja em execucao durante o patch." + RESET)

    config_file = args.config_file
    try:
        file_path, old_signkey, new_signkey, hwid, edition, version, authorize_file_output, dsa_params = load_config(config_file, args)
    except Exception as e:
        print(RED + f"Erro ao carregar configuracao: {e}" + RESET)
        input(GREY + "Press Enter to exit..." + RESET)
        return

    if file_path.lower() == "auto":
        installations = find_installations()
        if not installations:
            print(RED + "\nNenhuma instalacao do Ableton Live encontrada. Informe o caminho manualmente." + RESET)
            input(GREY + "Press Enter to exit..." + RESET)
            return
        print(WHITE + "\nInstalacoes do Ableton encontradas:" + RESET)
        for i, (path, name) in enumerate(installations):
            print(WHITE + f"{i+1}. " + WHITE + f"{name}" + GREY + f" em {path}" + RESET)
        try:
            selection = int(input(WHITE + "\nSelecione a instalacao para aplicar o patch: " + RED)) - 1
            if selection < 0 or selection >= len(installations):
                print(RED + "Selecao invalida. Usando a primeira instalacao." + RESET)
                selection = 0
            file_path = installations[selection][0]
            print(WHITE + f"Selecionado: {file_path}" + RESET)
        except ValueError:
            print(RED + "Entrada invalida. Usando a primeira instalacao encontrada." + RESET)
            file_path = installations[0][0]

    # Pula a geracao do arquivo de autorizacao no modo undo
    if not args.undo:
        if authorize_file_output.lower() == "auto":
            data_dirs = find_installation_data()
            if not data_dirs:
                config_dir = get_user_config_dir()
                default_dir = os.path.join(config_dir, "Ableton", f"Live {version} {edition}")
                unlock_dir = os.path.join(default_dir, "Unlock")
                os.makedirs(unlock_dir, exist_ok=True)
                authorize_file_output = os.path.join(unlock_dir, "Authorize.auz")
                print(WHITE + f"\nUsando local padrao do arquivo de autorizacao: " + WHITE + f"{authorize_file_output}" + RESET)
            else:
                print(WHITE + "\nDiretorios de dados do Ableton encontrados:" + RESET)
                for i, (path, name) in enumerate(data_dirs):
                    print(WHITE + f"{i+1}. " + WHITE + f"{name}" + GREY + f" em {path}" + RESET)
                try:
                    selection = int(input(WHITE + "\nSelecione o diretorio de dados: " + RESET)) - 1
                    if selection < 0 or selection >= len(data_dirs):
                        print(RED + "Selecao invalida. Usando o primeiro diretorio." + RESET)
                        selection = 0
                    unlock_dir = os.path.join(data_dirs[selection][0], "Unlock")
                    os.makedirs(unlock_dir, exist_ok=True)
                    authorize_file_output = os.path.join(unlock_dir, "Authorize.auz")
                    print(WHITE + f"Selecionado: " + GREY + f"{authorize_file_output}" + RESET)
                except ValueError:
                    print(RED + "Entrada invalida. Usando o primeiro diretorio de dados encontrado." + RESET)
                    unlock_dir = os.path.join(data_dirs[0][0], "Unlock")
                    os.makedirs(unlock_dir, exist_ok=True)
                    authorize_file_output = os.path.join(unlock_dir, "Authorize.auz")

        try:
            team_r2r_key = construct_key(dsa_params)
        except Exception as e:
            print(RED + f"Erro ao construir chave DSA: {e}" + RESET)
            input(GREY + "Press Enter to exit..." + RESET)
            return

        print(WHITE + "\nGerando chaves de autorizacao..." + RESET)
        try:
            lines = list(generate_all(team_r2r_key, edition, version, hwid))
            # Garante que o diretorio de saida exista
            os.makedirs(os.path.dirname(authorize_file_output), exist_ok=True)
            with open(authorize_file_output, "w", newline="\n") as f:
                f.write("\n".join(lines))
            print("Arquivo de autorizacao criado: " + WHITE + f"{authorize_file_output}" + RESET)
        except Exception as e:
            print(RED + f"Erro ao gerar chaves de autorizacao: {e}" + RESET)
            input(GREY + "Press Enter to exit..." + RESET)
            return

    print(WHITE + "\nAplicando patch no executavel..." + RESET)
    try:
        replace_signkey_in_file(file_path, old_signkey, new_signkey, args.undo)
        print(GREEN + "\nPatch concluido com sucesso!" + RESET)
        
        # Mostra instrucoes do arquivo de autorizacao e abertura da pasta apenas no modo normal
        if not args.undo:
            print(GREEN + "SUCESSO! Seu Ableton Live agora esta patchado." + RESET)
            print(WHITE + "\nPara concluir a ativacao:" + RESET)
            print(WHITE + "1. Inicie o Ableton Live" + RESET)
            print(WHITE + "2. Basta arrastar e soltar o arquivo " + YELLOW + "Authorize.auz" + WHITE + " na janela de ativacao" + RESET)
            print(YELLOW + "\nPronto! Nao e necessario copiar arquivos manualmente." + RESET)
            
            try:
                response = input(WHITE + "\nDeseja abrir a pasta que contem o Authorize.auz? (y/N): " + RESET).strip().lower()
                if response in ['y', 'yes']:
                    if open_folder(authorize_file_output):
                        print(GREEN + "Pasta aberta com sucesso!" + RESET)
                    else:
                        print(RED + "Nao foi possivel abrir a pasta automaticamente." + RESET)
                        print(WHITE + "Navegue ate a pasta manualmente. (geralmente na mesma pasta onde o arquivo python esta localizado, dentro da pasta 'output')" + RESET)
            except:
                pass  # Se a leitura falhar, apenas continua
                
        input(GREY + "\nPress Enter to exit..." + RESET)
    except Exception as e:
        print(RED + f"\nFalha no patch: {e}" + RESET)
        input(GREY + "Press Enter to exit..." + RESET)

if __name__ == "__main__":
    main()