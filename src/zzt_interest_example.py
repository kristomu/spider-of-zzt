import zzt_interesting

with open("zzt.zip", "rb") as zztfile:
	checker = zzt_interesting.ZZTInterestChecker()

	report = checker.check("./zzt.zip", "",zztfile.read(), 3)

	for result in report.results:
		print("Interesting:", str(result))

	for error in report.errors:
		print("Error:", str(error))