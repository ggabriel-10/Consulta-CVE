import pandas as pd
import requests
from deep_translator import GoogleTranslator

def get_cve_info(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def main():
    #Deve ser usada a planilha base.txt para que o script consulte
    df = pd.read_excel('base.xlsx', header=None, names=['CVE']) 
    cve_ids = df['CVE'].tolist()

    data = []
    for cve_id in cve_ids:
        cve_info = get_cve_info(cve_id)
        translator = GoogleTranslator(source='en', target='pt')

        if cve_info and 'vulnerabilities' in cve_info:
            vulnerabilities = cve_info['vulnerabilities']
            for vulnerability in vulnerabilities:
                cve = vulnerability['cve']
                cve_id = cve['id']
                print(f"{cve_id} - Concluído com Sucesso!")
                description = cve['descriptions'][0]['value']
                description = translator.translate(description)
                mitigation = cve.get('cisaRequiredAction', 'Mitigação não especificada')
                mitigation = translator.translate(mitigation)
                data.append({'CVE': cve_id, 'Descrição': description, 'Mitigação': mitigation})
        else:
            print(f"CVE {cve_id} não encontrada.")
    
    df_output = pd.DataFrame(data)
    df_output.to_csv('cves_output.csv', index=False, encoding='utf-8-sig')

    print("Script executado com sucesso!")

if __name__ == "__main__":
    main()
