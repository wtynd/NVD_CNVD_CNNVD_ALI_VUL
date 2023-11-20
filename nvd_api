import requests
import json
import os
import time
from datetime import datetime, timedelta

# 配置
API_KEY = ''  # 替换为您的API密钥
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 1000
RATE_LIMIT = 1.0  # API请求间的等待时间，根据API密钥的限制调整
TIMEOUT = 100.0
HEADERS = {"Accept-Language": "en-US", "User-Agent": "nvd-api-client-v2"}
BATCH_DAYS = 50  # 每批处理100天
LAST_RUN_FILE = '/home/vm-user/spider/add_spider/data/nvd/last_run.txt'

def get_last_processed_date():
    try:
        with open(LAST_RUN_FILE, 'r') as file:
            last_date = file.read().strip()
            return datetime.strptime(last_date, '%Y-%m-%dT%H:%M:%SZ')
    except FileNotFoundError:
        return datetime(1999, 1, 1)  # 默认开始日期

def set_last_processed_date(date):
    with open(LAST_RUN_FILE, 'w') as file:
        file.write(date.strftime('%Y-%m-%dT%H:%M:%SZ'))

def build_query(start_date, end_date):
    formatted_start_date = start_date.strftime('%Y-%m-%dT%H:%M:%SZ').replace(':', '%3A')
    formatted_end_date = end_date.strftime('%Y-%m-%dT%H:%M:%SZ').replace(':', '%3A')
    return f"pubStartDate={formatted_start_date}&pubEndDate={formatted_end_date}"

def get_cve_data(start_index, query=None):
    url = f"{BASE_URL}?resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}"
    if query:
        url += f"&{query}"
    response = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
    if response.status_code != 200:
        raise Exception(f"API请求失败，状态码: {response.status_code}")
    time.sleep(RATE_LIMIT)
    return response.json()

def save_cve_record(record, base_directory):
    cve_id = record['cve']['id']
    print(cve_id)
    year = cve_id.split('-')[1]
    directory = os.path.join(base_directory, year)
    os.makedirs(directory, exist_ok=True)
    file_path = os.path.join(directory, f'{cve_id}.json')
    with open(file_path, 'w') as file:
        json.dump(record, file, indent=4)
def process_batch(start_date, end_date, base_directory):
    query = build_query(start_date, end_date)
    start_index = 0
    more_data = True
    batch_success = False  # 标记批次是否成功

    while more_data:
        try:
            data = get_cve_data(start_index, query)
            if 'vulnerabilities' in data:
                for cve in data['vulnerabilities']:
                    save_cve_record(cve, base_directory)
                start_index += len(data['vulnerabilities'])
                more_data = start_index < data['totalResults']
                batch_success = True  # 批次成功
                time.sleep(3.1)
            else:
                more_data = False
        except Exception as e:
        
            print(f"发生错误: {e}")
            time.sleep(10)
            more_data = False  # 发生错误时停止当前批次

    return batch_success  # 返回批次是否成功

def main():
    base_directory = './data/nvd'
    last_processed_date = get_last_processed_date()
    end_date = datetime.now()
    current_date = last_processed_date

    while current_date < end_date:
        batch_end_date = min(current_date + timedelta(days=BATCH_DAYS), end_date)
        if process_batch(current_date, batch_end_date, base_directory):
            set_last_processed_date(batch_end_date)  # 仅在批次成功时更新日期
        current_date = batch_end_date

if __name__ == "__main__":
    main()

