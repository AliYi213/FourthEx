<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fo="http://www.w3.org/1999/XSL/Format">
    <xsl:template match="/">
        <fo:root>
            <fo:layout-master-set>
                <fo:simple-page-master master-name="A4" page-height="29.7cm" page-width="21cm" margin="2cm">
                    <fo:region-body/>
                </fo:simple-page-master>
            </fo:layout-master-set>

            <fo:page-sequence master-reference="A4">
                <fo:flow flow-name="xsl-region-body">
                    <fo:block font-size="14pt" font-weight="bold" text-align="center" space-after.optimum="20pt">
                        Product Catalog
                    </fo:block>
                    <fo:table border="1pt solid black" width="100%">
                        <fo:table-header>
                            <fo:table-row background-color="#b0c4de">
                                <fo:table-cell><fo:block>Name</fo:block></fo:table-cell>
                                <fo:table-cell><fo:block>Category</fo:block></fo:table-cell>
                                <fo:table-cell><fo:block>Price</fo:block></fo:table-cell>
                                <fo:table-cell><fo:block>Availability</fo:block></fo:table-cell>
                            </fo:table-row>
                        </fo:table-header>
                        <fo:table-body>
                            <xsl:for-each select="//div[@class='product']">
                                <fo:table-row>
                                    <fo:table-cell>
                                        <fo:block><xsl:value-of select="h2"/></fo:block>
                                    </fo:table-cell>
                                    <fo:table-cell>
                                        <fo:block><xsl:value-of select="p[1]"/></fo:block>
                                    </fo:table-cell>
                                    <fo:table-cell>
                                        <fo:block><xsl:value-of select="p[2]"/></fo:block>
                                    </fo:table-cell>
                                    <fo:table-cell>
                                        <fo:block><xsl:value-of select="p[3]"/></fo:block>
                                    </fo:table-cell>
                                </fo:table-row>
                            </xsl:for-each>
                        </fo:table-body>
                    </fo:table>
                </fo:flow>
            </fo:page-sequence>
        </fo:root>
    </xsl:template>
</xsl:stylesheet>
