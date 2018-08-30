test:
	py.test tests

lint:
	flake8 .

bumpversion:
	bumpversion minor setup.py

release:
	python setup.py sdist upload -r local
	python setup.py bdist_wheel upload -r local

coverage:
	pytest --cov-report term-missing --cov=pikciopou
