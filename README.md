# UnlockCat

Windows 11 22H2 이상을 대상으로 만든 파일·디스크·포트 점유 프로세스 검색 및 해제 도구입니다. GUI는 관리자 권한을 요청합니다. 별도의 콘솔 도구도 제공합니다. 주요 기능은 Windows 11 22H2(빌드 22621)에서 검증했습니다.

![화난 UnlockCat 고양이](src/UnlockCat/Assets/angry-cat.png)

## 사용

1. **파일**: 잠긴 파일의 전체 경로를 입력하고 **점유 프로세스 검색**을 누릅니다.
2. **이동식 디스크**: 드라이브를 선택하고 검색합니다. Windows에서 `Fixed`로 분류하는 USB 외장 디스크도 선택할 수 있습니다.
3. **포트**: `localhost:5000`, `5000`, `127.0.0.1:5000`, `[::1]:5000` 형식으로 검색합니다.

검색 결과에서 프로세스를 선택하면 점유 근거와 연결된 서비스를 볼 수 있습니다. **서비스 중지**는 선택한 Windows 서비스에 SCM 중지 요청을 보냅니다. **강제 종료**는 프로세스 인스턴스를 확인한 뒤 Windows `TerminateProcess`로 종료하고 실제 종료를 기다립니다. 두 동작 후 자동으로 다시 검색합니다. 공유 서비스 호스트에 여러 서비스가 있으면 중지할 서비스를 직접 선택합니다.

콘솔에서도 사용할 수 있습니다.

```powershell
unlockcat scan file "C:\temp\busy.txt"
unlockcat unlock file "C:\temp\busy.txt"
unlockcat scan volume E:\
unlockcat unlock volume E:\
unlockcat scan port localhost:5000
unlockcat unlock port localhost:5000
unlockcat scan service Spooler
unlockcat unlock service Spooler
```

`scan`은 읽기 전용입니다. `unlock`은 현재 점유를 다시 확인한 후 해당 프로세스를 강제 종료하거나 지정한 서비스를 중지합니다. 종료 상태 코드 `0`은 작업 성공/검색 완료, `1`은 실행 오류, `2`는 사용법 오류, `3`은 일부 검색 불가 또는 해제 미완료를 뜻합니다.

## 구현

- 파일: Windows Restart Manager와 Process Snapshotting API로 파일 핸들 및 메모리 매핑을 찾습니다. 파일 식별자를 조회할 수 있으면 하드 링크도 식별합니다.
- 디스크: 파일을 전부 순회하지 않고 프로세스의 열린 파일 핸들과 매핑 경로를 검사하여 해당 볼륨의 파일을 찾습니다.
- 포트: IP Helper의 TCP/UDP IPv4/IPv6 owner-PID 표를 읽습니다. 와일드카드 바인딩과 조회 가능한 소유 모듈 이름도 표시합니다.
- 서비스: Service Control Manager로 PID에 연결된 서비스 이름·상태를 조회하고 선택한 서비스를 중지합니다.
- 프로세스 종료: 재사용된 PID를 잘못 종료하지 않도록 생성 시간을 같은 프로세스 핸들에서 재확인합니다. 중요 시스템 프로세스는 종료하지 않습니다.

## 정확도와 제한

검색은 특정 순간의 상태입니다. Windows에서 보호하는 프로세스, 접근이 거부된 핸들, 커널 드라이버가 유지하는 점유는 사용자 모드 프로그램이 모두 열람하거나 강제 종료할 수 없습니다. 이런 경우 **검색 불완전** 또는 Windows 오류를 표시합니다. 파일/디스크 잠금이 해제되었는지는 종료 후 재검색으로 확인합니다.

공유 `svchost.exe`의 PID만으로는 어떤 서비스가 정확히 포트를 열었는지 단정할 수 없습니다. IP Helper의 소유 모듈 이름은 실행 파일·서비스·구성 요소 중 하나일 수 있으므로 그대로 표시합니다. 파일에 대해서 Restart Manager가 서비스 이름을 반환하면 그 이름을 **확인됨**으로 표시합니다. 서비스를 중지할 수 없더라도 별도 프로세스 강제 종료 버튼은 사용할 수 있지만, 공유 호스트의 다른 서비스도 함께 종료될 수 있습니다.

IPv6 와일드카드 소켓이 IPv4 주소도 점유하는지는 소켓의 dual-stack 설정에 따라 달라집니다. 확인되지 않은 `PotentialDualStack` 결과는 표시하되 자동 강제 종료 대상에서는 제외합니다. PID 0의 TCP 상태와 운영체제의 포트 제외 범위에는 종료할 사용자 프로세스가 없을 수 있습니다.

## 빌드

.NET 10 SDK가 필요합니다. Windows x64에서 다음 명령으로 빌드하거나 독립 실행형으로 게시할 수 있습니다.

```powershell
dotnet build src/UnlockCat/UnlockCat.csproj -c Release
dotnet build src/UnlockCat.Cli/UnlockCat.Cli.csproj -c Release
dotnet run --project tests/UnlockCat.Smoke/UnlockCat.Smoke.csproj -c Release
dotnet publish src/UnlockCat/UnlockCat.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/UnlockCat-win-x64
```

GUI 실행 파일의 아이콘은 [angry-cat.ico](src/UnlockCat/Assets/angry-cat.ico)입니다. 생성 원본 PNG도 함께 보관합니다.

## 주요 Windows API

- [Restart Manager](https://learn.microsoft.com/en-us/windows/win32/rstmgr/restart-manager-portal)
- [Process Snapshotting](https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot)
- [IP Helper owner-PID tables](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
- [Service Control Manager](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw)
- [TerminateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)
