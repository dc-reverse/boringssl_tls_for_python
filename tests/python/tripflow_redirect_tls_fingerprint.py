import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

import os
from tls_fingerprint import TLSHttpClient

cookies = {
    'optimizelyEndUserId': 'oeu1768137653730r0.6361866569449713',
    'kndctr_11B20CF953F3626B0A490D44_AdobeOrg_consent': 'general=in',
    '_gcl_au': '1.1.484746885.1768137662',
    '_ga': 'GA1.1.99756735.1768137663',
    'jumpseat_uid': 'ioWFQRSFKWzx9NHnFIcS0_',
    's_ecid': 'MCMID%7C19564282165998566922156347832840936361',
    'qantas_isDevice': 'type#desktop|os#Mac OS X',
    'AKA_A2': 'A',
    'bm_ss': 'ab8e18ef4e',
    'bm_so': '0106813BDAD37647B9669BB6119DA84F4AD4335DFC65A93D8A8A0AFC0BF1AD1F~YAAQPWYzuAHqdfqcAQAAx+MGWwdXbyZjNmKtsjGceQGGFdj/J5NTpBqTJEWKW3VIZv0KnWTU73r4CKsHZKwEeuaXnGpPNIg3jLgo2h/5QqSM9L9zAYA4tXeMA+i5lz7deKGWebi6y9NcaMNeqeDCeUtd1MR2L4rZh73sPq9rcCv9LcuMYv83JCuY2wEguCX7s/1wKjEmo2RQlOCyR4X/qpSXMefH3h0NsGO+sB9xDQS2+WFdNWNrCiPTeLp9LpahKJfo59Uq+jfUJa32hSOZPIXkR8RVr+rFV8aUVNtbTV8C2W/CyCMJKHyN9n6uRoUDSgux9t8kL7fKOOTBITUMYFdQt+4UUwNyFR0kzeFOEfJ9VMJL7fFw1C7bE2Xbuw16dlqFl91ND+Kel+Ru/vxwqjoX79h76I0t/iNGQjx+KV+VEdHD8wzc1S3ET5H1U+nKOkQtMypKAH5d1kubWTOcp4MBLg==',
    'bm_sz': '9E5FBE562B079B12790B5E24617CB7EA~YAAQPWYzuALqdfqcAQAAx+MGWx8DY9r59cJgTaI2KKOp/42TOgjlw4pLftFZKyN3FgKTc6lbZ2n+lLNHshtZyetqy/44wfNyOqFVRWoEeR6B50BixFt0hKzLDF8w1E9T7Zp3j3rd6n589UCvFZueLEeHIJ14pO+CBDH6UHv+/U+xtUmvoXgg5tBnheXw+9HiG8nbI1j/bb3SEgbNYvgjThGXw+wV4ABlzLbvJpjUYLSCICo6bLYLi5TJFS5E051Q1Y4vvL9cP8WycvAbkN3meVpHWnysFIegmgKntsSkjUVYUhxuEl6YnKq7Yn5+lfPAXP2189i2+/sJMfBa+47SSwzkQoaL7YDIxVG7Jh6OBwmOM4ZhjafxkBuevUDAzY1EXd/p4y3x6LngV//DsIDy~3225669~3356213',
    'ak_bmsc': '744972AC2C2DF99931989E582D9D4BB9~000000000000000000000000000000~YAAQPWYzuGvqdfqcAQAAY+kGWx/S4ATikabeY4mIHBJJzW/H6nT++DbZ2z0bImG37Gt6DUiua2UtAtTYwxoXx9o+TN5raaCK81rwqIqmJNDlPAMr3SrIdu29NghIpBFQgDVSVINv8HeMfdW7E6Vvq8G91xjes7saECAinsZNHWOcVff7896e1yHMGqXD1dNgRFwUaEPIwKMLVnPWEVhCv1oiruFvMUSaTZU2aK7SYp3XhrN4wtSW7Qz/Lu4uwAeeh5sUNDgc6f28vCLilw13DiEee9wSAC75tsEgkaWsDpCwmP5fKhs94Ktwh5vblsieNNSJUGRVHz9y6e+METJXrMCwszF7haeuan2JduKWREmcZSUNuZCilNP/loY2pStk8AtprR+tGy9hkemop8f6CXBnyDKaEVb+7owNQ/w175Zk/NiePcKj/GDwKrdyZ/XFWdeewxbxk3/lhklGhMlVVg==',
    'OptanonConsent': 'isGpcEnabled=0&datestamp=Sun+Apr+05+2026+08%3A24%3A35+GMT%2B0800+(%E4%B8%AD%E5%9B%BD%E6%A0%87%E5%87%86%E6%97%B6%E9%97%B4)&version=202510.2.0&browserGpcFlag=0&isIABGlobal=false&landingPath=https%3A%2F%2Fwww.qantas.com%2Fen-au&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1%2CC0004%3A1&hosts=H242%3A1%2CH40%3A1%2CH153%3A1%2CH284%3A1%2CH155%3A1%2CH277%3A1%2CH229%3A1%2CH152%3A1%2CH172%3A1%2CH241%3A1%2CH244%3A1%2CH202%3A1%2CH237%3A1%2CH204%3A1%2CH21%3A1%2CH205%3A1%2CH2%3A1%2CH286%3A1%2CH269%3A1%2CH159%3A1%2CH25%3A1%2CH274%3A1%2CH275%3A1%2CH31%3A1%2CH33%3A1%2CH3%3A1%2CH37%3A1%2CH4%3A1%2CH44%3A1%2CH173%3A1%2CH5%3A1%2CH50%3A1%2CH51%3A1%2CH276%3A1%2CH61%3A1%2CH6%3A1%2CH70%3A1%2CH272%3A1%2CH74%3A1%2CH75%3A1%2CH7%3A1%2CH81%3A1%2CH8%3A1%2CH270%3A1%2CH86%3A1%2CH9%3A1%2CH253%3A1%2CH278%3A1%2CH97%3A1%2CH273%3A1%2CH279%3A1%2CH271%3A1%2CH233%3A1%2CH109%3A1%2CH113%3A1%2CH114%3A1%2CH115%3A1%2CH280%3A1%2CH254%3A1%2CH126%3A1%2CH281%3A1%2CH14%3A1%2CH282%3A1%2CH140%3A1&genVendors=',
    'BIGipServer~etv_aere_prd~app__171_17_136_6__443~az_onya-prd_443_pool': '2356296458.47873.0000',
    'd96f0bb00e43b27d5d92872c8bdaa775': 'c01fb161559610d850b6423241d4c265',
    'JSESSION_QFBOOKING': 'y9R1j53wS7Rlks243Jn4tTiNQpatDcvSfCeK19aY!1775348677411.dljdmx',
    'DWM_XSITECODE': 'QFQFQFQF',
    'bm_s': 'YAAQPWYzuMvrdfqcAQAA/QsHWwUCUCWenw1qhZxP5DuvbeduQ6/sFo6JPmMhuJcRdaINGydcHdYQ2nxtdFXu/XulD+jlfhnC+xopNe4tDtN7CmtrkNBwbLRzzvf/R8P0qVAAGYzkJIJS41hEojHCdkO79S5edGDe0F8+NrKQx77RZnI7PepDbz2T73viwenyMyCCPdiy+VQ87F+0ukBWEybARgIoF2fcgzWHquVJ+rAR7vYZCHoymVS3AJetOZo39IHigH0U4GQB/gIsmZeEq+M8GV2j6XGoGtUCirwxteysFL1oHDqQp4gSxAqq0optYwfHdmAX4v1GsId1gDtQ4KPhirn9tBL9hzhe/PW+eA6RnZnaJCGklLTnx3VxHF5E7TvJWyHnM6rX7uuze6Yx4aWxglk7fSiLDcRzPDOXMm06E7FBqfThG3cd5pC5s9HsYBySOQdDEx5Gc6ad0nFAd+DHrECOv/JCGcHd7j8WN0us0j+bTJuI499mpU/biv/bQokr/nuy3V+NQ2rvZQDou6ViRO4kqPVg224Sx4dnr3Eaz9IOKaWj+YmC1SJEwgIbzQKCvl/tFg8/Uh1czI6PnaU4rJQRBiFqKpTR5i/8HopFGs3aDFJnlHp4OjoBqK8FPdVwMyQVsu2IAzMA6VtxytAyBYvI73sb1yqx+QmQWMDboCOshjG6EHO5qgt40otuUyKRH1OXVKwiyvPP3XxdJgspcIzbf2UU+G1O+e6BQYEvzVgrGN0l8gkTjjPZzpE1eiWw3Bf+Q5jCYQ0r3U4MSs2NaBMv5mad1/Cm2IZsWF1+7NwU8/n3zTZGQCvESubtLsJv/FVRduc/ulvIqOwM+FRFBnUSJUCUfgR+62Zc7HBn6jbGgOdbaFaGNfd9lJbnZyERrneM',
    'bm_sv': '44922B7EAC9AE08D08A5BB9336B97DA0~YAAQPWYzuMzrdfqcAQAA/gsHWx9QWT4+MJvSgRxVdLdQUSqfoeP1U7MvlqbLBMCODoYu44lv9YIex4+YS7UvoE12if+IhrS2+P/hFNvHyPiNcVaJAeVzgxdr5wfZqGHLY9RR/DE2KskNY5sxuRRUsER0HmAQC58cefLY4z5eM7EVhwN8C2TiZcO47kQQg5QaTSzebmQ7au/u4pIUX4OywY0RC7pqUdunfkFYVv7xWbBc2WgiRVeSPVBZ03d9423JAQ==~1',
    'kndctr_11B20CF953F3626B0A490D44_AdobeOrg_identity': 'CiYxOTU2NDI4MjE2NTk5ODU2NjkyMjE1NjM0NzgzMjg0MDkzNjM2MVIRCOuinNjVMxgBKgRTR1AzMAPwAeuinNjVMw==',
    'kndctr_11B20CF953F3626B0A490D44_AdobeOrg_cluster': 'sgp3',
    'qtspersisted': '_53ae5d8e98704aaab52baf531bc2c35f3e521a6fbb834131b85c852f52adc26d_152cd166312b45eebc36c967504c74a7_1775348684563_117093590457848137_1775348684563_1',
    '_abck': 'F741351E14A916561EA169486CAE0FC3~0~YAAQRmYzuH9CjQWdAQAAIG8HWw+/Q9GicUsBYxb+oTD1qoA9PxqH8OuEo8XENM5SoJLMsdgahFZgf9X9I3ZlnHkjEmvB+Tx8SWMA5Jp8P1/8JrrkWHyEoAHx43q/zo5CUYs7E31LwVXTPJhUSrgSP5+Oyv+qi+jlPliXkhHNydOiGw3eocDCsX3huTMv77BaIh/ZIsIz92v1U47wZBIatIiquEmZYTOMBuM1qrNlc2wUHyc+1YNSeiNn+wo/p1mjXRqtxLGb+xQ0LbhAmfb1mba6QAj2K2eGxWoDBGw1ZgKQSpMvjwBYsApCp0V1R/Pzg89TUpaSF06uka6ITarIwCWjaTl5Syh4VaJj36sl4OTLuYiWTN03jzL+1B2yM50IGljcokVfHEhSSlAzLxP6L+kBKj6uWqnX+/ePq5iezOAuzLvPMoxGnOdpC5hoVMWxUWXvjkQN7oUE2WSXo5VVOLRNvG+y4+vlBPM48gRRhqNFRE44TKevC65gimWdC3a7UxSm0YpE66n9hNM6iYUH46aDk9Fzq5kDI6PZmjk3mVnm92oqUaTxGHsGoVZd7u6v4hHq3pMpch6/EAS6OHkeXthCA21J5ZIybJDBQ7+Apg1vbcNF4EgumbcUQEhdC6mjj6zcaDN0w2Z97VeA561hxA==~-1~-1~-1~AAQAAAAF%2f%2f%2f%2f%2f6A5ydl8v2wnDNvCvm1fJaLUjTi1PWmsW6syVh4duL6Amr97evxymZ51iWxEcKawodDgFb4B7XBfVR38tbMqpYI+h+nDvdpFStJW~1775349127',
    'qtssession': '117093590457848137_1775348832371_1775348684563_9976_4bf7eb68e8a545dfba9911c430f9fc71',
    '_dd_s': 'rum=2&id=cd64f17f-d234-4850-a38f-7ad0f58a86db&created=1775348683813&expire=1775349734123',
    'usercontextGlobal': 'locale#en|region#AU|country#AU|dep#PVG|arr#ADL|tvlDates#202604180000',
    'selectionsGlobal': 'DATES:1776441600000-1-0-0#1776441600000-1-0-0|PORTS:PVG#ADL|PSGRS:1#0#0|TYPE:INT|SRCHBY:M|REGION:AU|FARE:ECO|PORTNAMES:Shanghai (Pudong)#Adelaide|TRIP:O|SHOWCLASSIC:false|CLASSICFRMLIST:false|CLASSICTOLIST:false',
    '_ga_R8JNV0W5NK': 'GS2.1.s1775348660' + os.getenv('o3', '') + os.getenv('g1', '') + os.getenv('t1775348834', '') + os.getenv('j39', '') + os.getenv('l0', '') + os.getenv('h0', ''),
}

headers = {
    'Host': 'book.qantas.com',
    'cache-control': 'max-age=0',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"',
    'origin': 'https://www.qantas.com',
    'content-type': 'application/x-www-form-urlencoded',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'sec-fetch-site': 'same-site',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-user': '?1',
    'sec-fetch-dest': 'document',
    'referer': 'https://www.qantas.com/',
    'accept-language': 'zh-CN,zh;q=0.9',
    'priority': 'u=0, i',
}

data = {
    'depAirports': 'PVG',
    'destAirports': 'ADL',
    'travelDates': '202604180000',
    'numberOfAdults': '1',
    'numberOfYoungAdults': '0',
    'numberOfChildren': '0',
    'numberOfInfants': '0',
    'travelClass': 'ECO',
    'searchOption': 'F',
    'QFdeviceType': 'desktop',
    'PAGE_FROM': '/bookingError/v1/redirect/en-au/book/flights#fsw-form',
    'USER_LANG': 'EN',
    'USER_LOCALE': 'EN_AU',
    'int_cam': 'au:bookflight:top:newfsw:en:flights',
}

# 构建 Cookie 字符串
cookie_str = '; '.join([f'{k}={v}' for k, v in cookies.items()])
headers['cookie'] = cookie_str

# 创建 TLSHttpClient - 使用 Chrome 浏览器指纹
client = TLSHttpClient(
    browser_type="chrome",  # 可选: chrome, firefox, safari, edge, random
    timeout=30.0,
    debug=True,  # 开启调试日志
)

response = client.post(
    'https://book.qantas.com/qf-booking/dyn/air/tripflow.redirect',
    headers=headers,
    body=data,  # 传入 dict 自动编码为 application/x-www-form-urlencoded
)

# 打印响应
print(f'Status Code: {response.status_code}')
print(f'HTTP Version: {response.http_version}')
print(f'Response: {response.text}')
