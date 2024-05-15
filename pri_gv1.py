import pandas as pd
import requests
from tabulate import tabulate

base_url_epss = "https://api.first.org/data/v1/epss"
url_known_exploited_vulnerabilities = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def obter_dados_api(url):
    try:
        resposta = requests.get(url)
        resposta.raise_for_status()  # Lança uma exceção para erros HTTP
        dados_json = resposta.json()
        return dados_json.get("data", [])
    except requests.exceptions.RequestException as e:
        print(f"Erro na solicitação: {e}")
        return None

def obter_epss_scores_para_cves(cves):
    cves_param = ",".join(cves)
    url = f"{base_url_epss}?cve={cves_param}"
    return obter_dados_api(url)

def obter_known_exploited_vulnerabilities(cve):
    dados_exploited_vulnerabilities = obter_dados_api(url_known_exploited_vulnerabilities)
    # Procurar pela CVE informada nos dados de vulnerabilidades exploradas conhecidas
    dado_exploited_vulnerabilities_correspondente = next(
        (dado_exploited for dado_exploited in dados_exploited_vulnerabilities if cve in dado_exploited.get('cveID', '')),
        None
    )
    return dados_exploited_vulnerabilities

if __name__ == "__main__":
    # Ler a planilha Excel
    try:
        df = pd.read_excel(r"C:\Users\xpto\Documents\DIP\Pasta1.xlsx")  # Substitua pelo caminho da sua planilha
    except FileNotFoundError:
        print("Arquivo não encontrado.")
        exit()
    
    # Obter a lista de CVEs da planilha
    cves = df['CVE'].tolist()

    # Preparar os dados para a tabela
    dados = []

    for cve in cves:
        # Obter os EPSS scores para a CVE
        epss_scores = obter_epss_scores_para_cves([cve])

        # Obter dados de vulnerabilidades exploradas conhecidas para a CVE
        exploited_vulnerabilities = obter_known_exploited_vulnerabilities(cve)

        # Adicionar os resultados do EPSS à lista de dados
        if epss_scores:
            cve_epss = epss_scores[0].get('cve')
            epss_value = f"{float(epss_scores[0].get('epss')) * 100:.2f}%"  # Convertendo para porcentagem
            dados.append(["EPSS", cve_epss, epss_value])

            # Verificar se há dados do CISA KEV para a CVE
            if exploited_vulnerabilities:
                cve_cisa_kev = exploited_vulnerabilities.get('cveID', 'N/A')
                detalhes_cisa_kev = exploited_vulnerabilities.get('details', 'N/A')
                dados[-1].extend(["CISA KEV", cve_cisa_kev, detalhes_cisa_kev])
            else:
                dados[-1].extend(["CISA KEV", "N/A", "N/A"])
        else:
            dados.append(["EPSS", cve, "N/A", "N/A"])

    # Exibir os resultados em forma de tabela
    headers = ["Fonte", "CVE", "Valor (EPSS)", "Fonte", "CVE", "Detalhes (CISA KEV)"]
    print(tabulate(dados, headers=headers, tablefmt="grid"))
