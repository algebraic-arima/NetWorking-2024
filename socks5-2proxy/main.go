package main

func main() {
	go runProxyServer()
	runProxyClient()
}
