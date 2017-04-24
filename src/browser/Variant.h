#ifndef VARIANT_H
#define VARIANT_H

#include <QtCore>

QVariantMap qo2qv( const QObject* object, const QStringList& ignoredProperties = QStringList(QString(QLatin1String("objectName"))) );

#endif // VARIANT_H